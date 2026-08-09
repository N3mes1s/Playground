import Foundation
import SwiftUI

/// Models the app offers. Opus 5 is the default; the cheaper tiers are there
/// for quick summaries where the extra capability isn't needed.
enum ClaudeModel: String, CaseIterable, Identifiable {
    case opus5 = "claude-opus-5"
    case sonnet5 = "claude-sonnet-5"
    case haiku45 = "claude-haiku-4-5"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .opus5: return "Claude Opus 5"
        case .sonnet5: return "Claude Sonnet 5"
        case .haiku45: return "Claude Haiku 4.5"
        }
    }

    var blurb: String {
        switch self {
        case .opus5: return "Deepest analysis. Default."
        case .sonnet5: return "Near-Opus quality, lower cost."
        case .haiku45: return "Fastest and cheapest."
        }
    }

    /// `output_config.effort` is not accepted on Haiku 4.5.
    var supportsEffort: Bool {
        self != .haiku45
    }
}

enum ClaudeEffort: String, CaseIterable, Identifiable {
    case low, medium, high

    var id: String { rawValue }
    var displayName: String { rawValue.capitalized }
}

/// Preferences plus keychain-backed secrets.
///
/// These are `@Published` rather than `@AppStorage`: `@AppStorage` is a
/// `DynamicProperty` designed for views, and inside an `ObservableObject` it
/// persists but never fires `objectWillChange`, so views wouldn't redraw.
@MainActor
final class AppSettings: ObservableObject {
    private let defaults: UserDefaults = .standard

    @Published var owner: String { didSet { defaults.set(owner, forKey: "repoOwner") } }
    @Published var repo: String { didSet { defaults.set(repo, forKey: "repoName") } }
    @Published var branch: String { didSet { defaults.set(branch, forKey: "repoBranch") } }
    @Published var modelID: String { didSet { defaults.set(modelID, forKey: "claudeModel") } }
    @Published var effortID: String { didSet { defaults.set(effortID, forKey: "claudeEffort") } }

    /// Bumped when a secret changes so views re-evaluate `hasAnthropicKey`.
    @Published private(set) var secretsRevision: Int = 0

    init() {
        let defaults = UserDefaults.standard
        owner = defaults.string(forKey: "repoOwner") ?? "N3mes1s"
        repo = defaults.string(forKey: "repoName") ?? "Playground"
        branch = defaults.string(forKey: "repoBranch") ?? "main"
        modelID = defaults.string(forKey: "claudeModel") ?? ClaudeModel.opus5.rawValue
        effortID = defaults.string(forKey: "claudeEffort") ?? ClaudeEffort.medium.rawValue
    }

    var model: ClaudeModel {
        get { ClaudeModel(rawValue: modelID) ?? .opus5 }
        set { modelID = newValue.rawValue }
    }

    var effort: ClaudeEffort {
        get { ClaudeEffort(rawValue: effortID) ?? .medium }
        set { effortID = newValue.rawValue }
    }

    var anthropicAPIKey: String? { KeychainStore.read(.anthropicAPIKey) }
    var githubToken: String? { KeychainStore.read(.githubToken) }
    var hasAnthropicKey: Bool { anthropicAPIKey != nil }

    func setAnthropicAPIKey(_ value: String) {
        KeychainStore.write(value, for: .anthropicAPIKey)
        secretsRevision += 1
    }

    func setGitHubToken(_ value: String) {
        KeychainStore.write(value, for: .githubToken)
        secretsRevision += 1
    }

    func makeGitHubClient() -> GitHubClient {
        GitHubClient(owner: owner, repo: repo, branch: branch, token: githubToken)
    }

    func makeClaudeClient() throws -> ClaudeClient {
        guard let key = anthropicAPIKey else { throw ClaudeError.missingAPIKey }
        return ClaudeClient(apiKey: key)
    }
}
