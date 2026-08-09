import Foundation

enum ClaudeError: LocalizedError {
    case missingAPIKey
    case http(status: Int, type: String?, message: String?)
    case refused(category: String?, explanation: String?)
    case transport(String)

    var errorDescription: String? {
        switch self {
        case .missingAPIKey:
            return "No Anthropic API key yet. Add one in Settings."
        case .http(let status, let type, let message):
            let detail = [type, message].compactMap { $0 }.joined(separator: ": ")
            return detail.isEmpty ? "Anthropic API returned \(status)." : "\(status) — \(detail)"
        case .refused(let category, let explanation):
            let suffix = explanation.map { " \($0)" } ?? ""
            if let category {
                return "Claude declined this request (\(category))." + suffix
            }
            return "Claude declined this request." + suffix
        case .transport(let message):
            return message
        }
    }
}

/// Raw-HTTP client for the Messages API. There is no official Anthropic SDK for
/// Swift, so this speaks the wire format directly.
///
/// Note on auth: the key lives in the Keychain on-device, which is fine for a
/// personal experiment but is *not* how a shipping app should do it — anything
/// on the device can ultimately be extracted. Production apps should proxy
/// through a backend that holds the key.
struct ClaudeClient {
    let apiKey: String

    private static let endpoint = URL(string: "https://api.anthropic.com/v1/messages")!
    private static let apiVersion = "2023-06-01"

    /// Streams the assistant's text back token-by-token.
    ///
    /// `max_tokens` bounds thinking *and* response text together. Thinking is on
    /// by default on Opus 5, so this stays generous rather than sized to the
    /// expected answer.
    func streamText(
        system: String?,
        prompt: String,
        model: ClaudeModel,
        effort: ClaudeEffort,
        maxTokens: Int = 16_000
    ) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let request = try makeRequest(
                        system: system,
                        prompt: prompt,
                        model: model,
                        effort: effort,
                        maxTokens: maxTokens
                    )
                    let (bytes, response) = try await URLSession.shared.bytes(for: request)
                    try await validate(response: response, bytes: bytes)

                    for try await line in bytes.lines {
                        try Task.checkCancellation()
                        guard line.hasPrefix("data:") else { continue }

                        let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                        guard !payload.isEmpty, payload != "[DONE]" else { continue }

                        let event = try JSONDecoder().decode(
                            StreamEvent.self, from: Data(payload.utf8)
                        )

                        switch event.type {
                        case "content_block_delta":
                            // Thinking deltas are ignored: `display` defaults to
                            // omitted, so they carry no text anyway.
                            if event.delta?.type == "text_delta", let text = event.delta?.text {
                                continuation.yield(text)
                            }
                        case "message_delta":
                            if event.delta?.stopReason == "refusal" {
                                throw ClaudeError.refused(
                                    category: event.delta?.stopDetails?.category,
                                    explanation: event.delta?.stopDetails?.explanation
                                )
                            }
                        case "error":
                            throw ClaudeError.http(
                                status: 200,
                                type: event.error?.type,
                                message: event.error?.message
                            )
                        case "message_stop":
                            continuation.finish()
                            return
                        default:
                            break
                        }
                    }
                    continuation.finish()
                } catch is CancellationError {
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }

            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: - Plumbing

    private func makeRequest(
        system: String?,
        prompt: String,
        model: ClaudeModel,
        effort: ClaudeEffort,
        maxTokens: Int
    ) throws -> URLRequest {
        var request = URLRequest(url: Self.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue(Self.apiVersion, forHTTPHeaderField: "anthropic-version")
        request.timeoutInterval = 300

        let body = MessagesRequest(
            model: model.rawValue,
            maxTokens: maxTokens,
            stream: true,
            system: system,
            outputConfig: model.supportsEffort ? OutputConfig(effort: effort.rawValue) : nil,
            messages: [.init(role: "user", content: prompt)]
        )
        request.httpBody = try JSONEncoder().encode(body)
        return request
    }

    private func validate(response: URLResponse, bytes: URLSession.AsyncBytes) async throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard !(200...299).contains(http.statusCode) else { return }

        // The error body arrives on the same byte stream; drain it for the message.
        var raw = ""
        for try await line in bytes.lines { raw += line }

        let decoded = try? JSONDecoder().decode(ErrorEnvelope.self, from: Data(raw.utf8))
        throw ClaudeError.http(
            status: http.statusCode,
            type: decoded?.error.type,
            message: decoded?.error.message ?? (raw.isEmpty ? nil : raw)
        )
    }
}

// MARK: - Wire types

private struct MessagesRequest: Encodable {
    struct Message: Encodable {
        let role: String
        let content: String
    }

    let model: String
    let maxTokens: Int
    let stream: Bool
    let system: String?
    let outputConfig: OutputConfig?
    let messages: [Message]

    private enum CodingKeys: String, CodingKey {
        case model, stream, system, messages
        case maxTokens = "max_tokens"
        case outputConfig = "output_config"
    }
}

private struct OutputConfig: Encodable {
    let effort: String
}

private struct ErrorEnvelope: Decodable {
    struct APIError: Decodable {
        let type: String?
        let message: String?
    }

    let error: APIError
}

private struct StreamEvent: Decodable {
    struct Delta: Decodable {
        let type: String?
        let text: String?
        let stopReason: String?
        let stopDetails: StopDetails?

        private enum CodingKeys: String, CodingKey {
            case type, text
            case stopReason = "stop_reason"
            case stopDetails = "stop_details"
        }
    }

    struct StopDetails: Decodable {
        let category: String?
        let explanation: String?
    }

    struct APIError: Decodable {
        let type: String?
        let message: String?
    }

    let type: String
    let delta: Delta?
    let error: APIError?
}
