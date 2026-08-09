import SwiftUI

/// Navigation routes. Directories and files are pushed by path so the browser
/// can recurse to any depth.
struct DirectoryRoute: Hashable {
    let path: String
    let title: String
}

struct FileRoute: Hashable {
    let path: String
    let name: String
    let isMarkdown: Bool
}

struct ExperimentListView: View {
    @EnvironmentObject private var settings: AppSettings
    @StateObject private var store = ExperimentStore()

    @State private var query = ""
    @State private var showingSettings = false
    @State private var showingRepoReadme = false

    private var filtered: [Experiment] {
        guard !query.isEmpty else { return store.experiments }
        return store.experiments.filter {
            $0.name.localizedCaseInsensitiveContains(query)
                || ($0.summary?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if store.isLoading && store.experiments.isEmpty {
                    ProgressView("Loading experiments…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let message = store.errorMessage, store.experiments.isEmpty {
                    ErrorStateView(message: message) {
                        Task { await store.load(using: settings.makeGitHubClient()) }
                    }
                } else {
                    list
                }
            }
            .navigationTitle("\(settings.repo)")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showingRepoReadme = true
                    } label: {
                        Label("About", systemImage: "info.circle")
                    }
                    .disabled(store.rootReadme == nil)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showingSettings = true
                    } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                }
            }
            .navigationDestination(for: Experiment.self) { experiment in
                ExperimentDetailView(experiment: experiment)
            }
            .navigationDestination(for: DirectoryRoute.self) { route in
                FileBrowserView(path: route.path, title: route.title)
            }
            .navigationDestination(for: FileRoute.self) { route in
                FileViewerView(route: route)
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView()
                    .environmentObject(settings)
            }
            .sheet(isPresented: $showingRepoReadme) {
                NavigationStack {
                    ScrollView {
                        MarkdownView(markdown: store.rootReadme ?? "")
                            .padding()
                    }
                    .navigationTitle("README")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Done") { showingRepoReadme = false }
                        }
                    }
                }
            }
        }
        .task {
            await store.loadIfNeeded(using: settings.makeGitHubClient())
        }
    }

    private var list: some View {
        List {
            if let message = store.errorMessage {
                Section {
                    Label(message, systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                ForEach(filtered) { experiment in
                    NavigationLink(value: experiment) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(experiment.name)
                                .font(.headline)
                            if let summary = experiment.summary {
                                Text(summary)
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(3)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            } header: {
                Text("\(store.experiments.count) experiments")
            } footer: {
                Text("Directories in \(settings.owner)/\(settings.repo) on \(settings.branch). "
                     + "Descriptions come from the root README table.")
            }
        }
        .listStyle(.insetGrouped)
        .searchable(text: $query, prompt: "Search experiments")
        .refreshable {
            await store.load(using: settings.makeGitHubClient())
        }
    }
}

struct ErrorStateView: View {
    let message: String
    let retry: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(message)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 32)
            Button("Try Again", action: retry)
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
