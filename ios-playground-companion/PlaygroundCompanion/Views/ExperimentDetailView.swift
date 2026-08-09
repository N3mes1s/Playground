import SwiftUI

/// One experiment: its README, plus a jump into the file browser.
struct ExperimentDetailView: View {
    let experiment: Experiment

    @EnvironmentObject private var settings: AppSettings
    @State private var readme: String?
    @State private var readmeName: String?
    @State private var isLoading = true
    @State private var errorMessage: String?
    @State private var askingClaude = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header

                if isLoading {
                    ProgressView().frame(maxWidth: .infinity)
                } else if let readme {
                    MarkdownView(markdown: readme)
                } else {
                    ContentUnavailableView(
                        "No README",
                        systemImage: "doc.questionmark",
                        description: Text(errorMessage
                            ?? "This experiment has no README.md — browse its files instead.")
                    )
                }
            }
            .padding()
        }
        .navigationTitle(experiment.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    askingClaude = true
                } label: {
                    Label("Ask Claude", systemImage: "sparkles")
                }
                .disabled(readme == nil)
            }
        }
        .sheet(isPresented: $askingClaude) {
            if let readme {
                AskClaudeView(
                    documentTitle: readmeName ?? "\(experiment.name)/README.md",
                    documentText: readme
                )
                .environmentObject(settings)
            }
        }
        .task { await load() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let summary = experiment.summary {
                Text(summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            NavigationLink(value: DirectoryRoute(path: experiment.path, title: experiment.name)) {
                Label("Browse files", systemImage: "folder")
            }
            .buttonStyle(.bordered)
            Divider()
        }
    }

    /// READMEs aren't always spelled the same way; try the common casings.
    private func load() async {
        isLoading = true
        defer { isLoading = false }

        let client = settings.makeGitHubClient()
        for candidate in ["README.md", "readme.md", "Readme.md"] {
            let path = "\(experiment.path)/\(candidate)"
            if let text = try? await client.fetchText(path: path) {
                readme = text
                readmeName = path
                errorMessage = nil
                return
            }
        }
        errorMessage = nil
    }
}
