import SwiftUI

/// Recursive directory listing. Pushes deeper directories as new routes and
/// text files into the viewer.
struct FileBrowserView: View {
    let path: String
    let title: String

    @EnvironmentObject private var settings: AppSettings
    @State private var entries: [RepoEntry] = []
    @State private var isLoading = true
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if isLoading && entries.isEmpty {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let errorMessage, entries.isEmpty {
                ErrorStateView(message: errorMessage) {
                    Task { await load() }
                }
            } else {
                List(entries) { entry in
                    row(for: entry)
                }
                .listStyle(.plain)
                .refreshable { await load() }
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .task { await load() }
    }

    @ViewBuilder
    private func row(for entry: RepoEntry) -> some View {
        switch entry.type {
        case .dir:
            NavigationLink(value: DirectoryRoute(path: entry.path, title: entry.name)) {
                label(for: entry)
            }
        case .file where entry.isProbablyText:
            NavigationLink(value: FileRoute(
                path: entry.path,
                name: entry.name,
                isMarkdown: entry.isMarkdown
            )) {
                label(for: entry)
            }
        default:
            label(for: entry)
                .foregroundStyle(.secondary)
        }
    }

    private func label(for entry: RepoEntry) -> some View {
        HStack(spacing: 12) {
            Image(systemName: entry.systemImageName)
                .foregroundStyle(entry.type == .dir ? Color.accentColor : .secondary)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.name)
                if entry.type == .file, let size = entry.size {
                    Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            entries = try await settings.makeGitHubClient().listDirectory(path: path)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
