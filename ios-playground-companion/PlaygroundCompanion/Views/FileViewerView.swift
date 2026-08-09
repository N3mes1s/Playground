import SwiftUI

/// Shows one file: rendered when it's markdown, monospaced source otherwise.
struct FileViewerView: View {
    let route: FileRoute

    @EnvironmentObject private var settings: AppSettings
    @State private var text: String?
    @State private var isLoading = true
    @State private var errorMessage: String?
    @State private var renderMarkdown: Bool
    @State private var askingClaude = false

    init(route: FileRoute) {
        self.route = route
        _renderMarkdown = State(initialValue: route.isMarkdown)
    }

    var body: some View {
        Group {
            if isLoading {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let errorMessage {
                ErrorStateView(message: errorMessage) {
                    Task { await load() }
                }
            } else if let text {
                ScrollView {
                    if renderMarkdown {
                        MarkdownView(markdown: text)
                            .padding()
                    } else {
                        ScrollView(.horizontal, showsIndicators: true) {
                            Text(text)
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                                .padding()
                        }
                    }
                }
            }
        }
        .navigationTitle(route.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if route.isMarkdown {
                    Button {
                        renderMarkdown.toggle()
                    } label: {
                        Label(
                            renderMarkdown ? "Show source" : "Render",
                            systemImage: renderMarkdown ? "chevron.left.forwardslash.chevron.right"
                                                        : "doc.richtext"
                        )
                    }
                }
                Button {
                    askingClaude = true
                } label: {
                    Label("Ask Claude", systemImage: "sparkles")
                }
                .disabled(text == nil)
            }
        }
        .sheet(isPresented: $askingClaude) {
            if let text {
                AskClaudeView(documentTitle: route.path, documentText: text)
                    .environmentObject(settings)
            }
        }
        .task { await load() }
    }

    private func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            text = try await settings.makeGitHubClient().fetchText(path: route.path)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
