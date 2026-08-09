import Foundation

/// Loads the repo's top-level directories and pairs each with the description
/// the root README's experiments table gives it.
@MainActor
final class ExperimentStore: ObservableObject {
    @Published private(set) var experiments: [Experiment] = []
    @Published private(set) var rootReadme: String?
    @Published private(set) var isLoading = false
    @Published var errorMessage: String?

    private var hasLoaded = false

    func loadIfNeeded(using client: GitHubClient) async {
        guard !hasLoaded else { return }
        await load(using: client)
    }

    func load(using client: GitHubClient) async {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let entries = try await client.listDirectory()
            let readme = try? await client.fetchText(path: "README.md")
            let summaries = readme.map(ReadmeTableParser.summaries(in:)) ?? [:]

            experiments = entries
                .filter { $0.type == .dir && !$0.name.hasPrefix(".") }
                .map { entry in
                    Experiment(
                        name: entry.name,
                        path: entry.path,
                        summary: summaries[entry.name.lowercased()]
                    )
                }
            rootReadme = readme
            hasLoaded = true
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

/// Pulls `| directory | description |` rows out of the root README so the list
/// can show what each experiment is without opening it.
enum ReadmeTableParser {
    /// Keyed by lowercased directory name.
    static func summaries(in markdown: String) -> [String: String] {
        var result: [String: String] = [:]

        for rawLine in markdown.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("|") else { continue }

            let cells = line
                .split(separator: "|", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            guard cells.count >= 2 else { continue }

            // Skip the header and the |---|---| separator row.
            let separator = CharacterSet(charactersIn: "-: ")
            if cells.allSatisfy({ $0.unicodeScalars.allSatisfy(separator.contains) }) { continue }

            guard let name = directoryName(from: cells[0]) else { continue }
            let description = stripInlineMarkdown(cells[1])
            guard !description.isEmpty else { continue }
            result[name.lowercased()] = description
        }

        return result
    }

    /// Handles the shapes the table actually uses: `` [`dir/`](dir/) ``,
    /// `[dir](./dir/)`, `` `dir/` ``, and a bare `dir`.
    private static func directoryName(from cell: String) -> String? {
        var text = cell

        if let linkTextRange = text.range(of: #"\[([^\]]+)\]"#, options: .regularExpression) {
            text = String(text[linkTextRange]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        }

        text = text.replacingOccurrences(of: "`", with: "")
        text = text.replacingOccurrences(of: "./", with: "")
        text = text.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))

        guard !text.isEmpty, !text.contains(" ") else { return nil }
        return text
    }

    private static func stripInlineMarkdown(_ text: String) -> String {
        var out = text
        // [label](url) -> label
        out = out.replacingOccurrences(
            of: #"\[([^\]]*)\]\([^)]*\)"#,
            with: "$1",
            options: .regularExpression
        )
        out = out.replacingOccurrences(of: "`", with: "")
        out = out.replacingOccurrences(of: "**", with: "")
        return out.trimmingCharacters(in: .whitespaces)
    }
}
