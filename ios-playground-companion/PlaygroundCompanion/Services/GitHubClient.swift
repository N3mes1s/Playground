import Foundation

enum GitHubError: LocalizedError {
    case badPath(String)
    case http(status: Int, message: String?)
    case rateLimited(resetAt: Date?)
    case notAFile(String)
    case undecodableText(String)

    var errorDescription: String? {
        switch self {
        case .badPath(let path):
            return "Couldn't build a URL for “\(path)”."
        case .http(let status, let message):
            if let message, !message.isEmpty {
                return "GitHub returned \(status): \(message)"
            }
            return "GitHub returned \(status)."
        case .rateLimited(let resetAt):
            guard let resetAt else {
                return "GitHub rate limit reached. Add a personal access token in Settings."
            }
            let formatter = DateFormatter()
            formatter.timeStyle = .short
            return "GitHub rate limit reached — resets at \(formatter.string(from: resetAt)). "
                + "Add a personal access token in Settings to raise the limit."
        case .notAFile(let path):
            return "“\(path)” is a directory, not a file."
        case .undecodableText(let name):
            return "“\(name)” isn't UTF-8 text, so it can't be shown here."
        }
    }
}

/// Read-only client for the GitHub contents API.
///
/// Unauthenticated requests are limited to 60/hour per IP, which is enough for
/// casual browsing; a token in Settings raises it to 5,000/hour.
struct GitHubClient {
    let owner: String
    let repo: String
    let branch: String
    let token: String?

    // Computed, not stored: a private *stored* property would make the
    // synthesized memberwise initializer private too.
    private var session: URLSession { .shared }

    /// Lists a directory. Pass an empty path for the repository root.
    func listDirectory(path: String = "") async throws -> [RepoEntry] {
        let contents = try await fetchContents(path: path)
        switch contents {
        case .directory(let entries):
            return entries.sorted { lhs, rhs in
                if (lhs.type == .dir) != (rhs.type == .dir) { return lhs.type == .dir }
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
        case .file(let file):
            throw GitHubError.notAFile(file.path)
        }
    }

    /// Fetches a file as text. Files over 1 MB come back with an empty `content`
    /// field, so those fall through to the raw download URL.
    func fetchText(path: String) async throws -> String {
        let contents = try await fetchContents(path: path)
        guard case .file(let file) = contents else {
            throw GitHubError.notAFile(path)
        }
        if let text = file.decodedText { return text }

        guard let url = file.downloadURL else {
            throw GitHubError.undecodableText(file.name)
        }
        let (data, response) = try await session.data(for: request(url: url, raw: true))
        try validate(response: response, data: data)
        guard let text = String(data: data, encoding: .utf8) else {
            throw GitHubError.undecodableText(file.name)
        }
        return text
    }

    // MARK: - Plumbing

    private func fetchContents(path: String) async throws -> RepoContents {
        let trimmed = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        var components = URLComponents()
        components.scheme = "https"
        components.host = "api.github.com"
        components.path = "/repos/\(owner)/\(repo)/contents/\(trimmed)"
        components.queryItems = [URLQueryItem(name: "ref", value: branch)]

        guard let url = components.url else { throw GitHubError.badPath(path) }

        let (data, response) = try await session.data(for: request(url: url, raw: false))
        try validate(response: response, data: data)
        return try JSONDecoder().decode(RepoContents.self, from: data)
    }

    private func request(url: URL, raw: Bool) -> URLRequest {
        var request = URLRequest(url: url)
        request.setValue(raw ? "application/vnd.github.raw" : "application/vnd.github+json",
                         forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        if let token, !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard !(200...299).contains(http.statusCode) else { return }

        // 403/429 with a zeroed remaining count is the rate limit, not a
        // permissions problem — worth saying so explicitly.
        let remaining = http.value(forHTTPHeaderField: "x-ratelimit-remaining")
        if (http.statusCode == 403 || http.statusCode == 429), remaining == "0" {
            let reset = http.value(forHTTPHeaderField: "x-ratelimit-reset").flatMap(Double.init)
            throw GitHubError.rateLimited(resetAt: reset.map { Date(timeIntervalSince1970: $0) })
        }

        struct APIMessage: Decodable { let message: String? }
        let message = try? JSONDecoder().decode(APIMessage.self, from: data).message
        throw GitHubError.http(status: http.statusCode, message: message)
    }
}
