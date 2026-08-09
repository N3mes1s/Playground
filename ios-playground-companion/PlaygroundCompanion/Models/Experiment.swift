import Foundation

/// A top-level directory in the Playground repo, paired with the description
/// the root README gives it (when there is one).
struct Experiment: Identifiable, Hashable {
    let name: String
    let path: String
    var summary: String?

    var id: String { path }
}

/// One entry returned by the GitHub contents API.
struct RepoEntry: Identifiable, Hashable, Decodable {
    enum Kind: String, Decodable {
        case file
        case dir
        case symlink
        case submodule
    }

    let name: String
    let path: String
    let type: Kind
    let size: Int?
    let downloadURL: URL?

    var id: String { path }

    private enum CodingKeys: String, CodingKey {
        case name, path, type, size
        case downloadURL = "download_url"
    }

    /// Files the app can render meaningfully. Everything else is listed but
    /// opens as plain text.
    var isMarkdown: Bool {
        let ext = (name as NSString).pathExtension.lowercased()
        return ext == "md" || ext == "markdown"
    }

    var isProbablyText: Bool {
        let textExtensions: Set<String> = [
            "md", "markdown", "txt", "py", "swift", "js", "ts", "go", "rs", "rb",
            "java", "c", "h", "cpp", "sh", "yml", "yaml", "json", "toml", "cfg",
            "ini", "html", "css", "sql", "log",
        ]
        let ext = (name as NSString).pathExtension.lowercased()
        return ext.isEmpty ? false : textExtensions.contains(ext)
    }

    var systemImageName: String {
        switch type {
        case .dir: return "folder"
        case .symlink, .submodule: return "arrow.triangle.branch"
        case .file: return isMarkdown ? "doc.richtext" : "doc.text"
        }
    }
}

/// The GitHub contents API returns a single object for a file and an array for
/// a directory. This handles both.
enum RepoContents: Decodable {
    case file(RepoFileContent)
    case directory([RepoEntry])

    init(from decoder: Decoder) throws {
        if let entries = try? [RepoEntry](from: decoder) {
            self = .directory(entries)
            return
        }
        self = .file(try RepoFileContent(from: decoder))
    }
}

struct RepoFileContent: Decodable {
    let name: String
    let path: String
    let size: Int
    let encoding: String?
    let content: String?
    let downloadURL: URL?

    private enum CodingKeys: String, CodingKey {
        case name, path, size, encoding, content
        case downloadURL = "download_url"
    }

    /// Base64 payloads from GitHub are line-wrapped, which `Data(base64Encoded:)`
    /// rejects unless told to ignore unknown characters.
    var decodedText: String? {
        guard encoding == "base64", let content else { return nil }
        guard let data = Data(base64Encoded: content, options: .ignoreUnknownCharacters) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
