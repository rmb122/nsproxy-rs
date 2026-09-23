# Project Guidelines

## Engineering and Communication

1. Follow KISS and YAGNI. Keep solutions simple and avoid unnecessary code or abstractions.
2. Keep code modular and organize it by functionality. Avoid files containing thousands of lines.
3. Group tests for the same functionality by scenario, give each test layer a clear responsibility, reuse shared fixtures and helpers, and avoid duplicate coverage. When moving tests, update test configuration, type-checking scope, and documentation together.
4. When fixing a bug, identify and explain its root cause, fix it in the module responsible for the behavior, and add necessary regression tests covering the actual triggering scenario.
5. Use Chinese only when communicating with the user, including progress updates, reports, root cause explanations, and validation results. Clearly describe what changed, why it changed, and the results of checks actually performed.
6. Use English for code comments and Git commit messages, including both the subject and body.
7. Use ASCII punctuation and symbols instead of Chinese or full-width punctuation and symbols, including in Chinese replies to the user.
8. Separate adjacent Rust functions and methods with one blank line. Place the blank line before any documentation comments or attributes attached to the next function.

## TCP Closure Semantics (Explicit User Requirement)

Outbound TCP and published-port TCP terminate the entire forwarding connection after either direction reaches EOF or half-closes, subject to the existing buffer-drain conditions. Keeping the other direction open independently after a half-close is intentionally unsupported.

- Outbound connections (`src/event_loop/outbound.rs`): After the application shuts down its write side and the receive buffer drains, the implementation may immediately call `abort()` and release the upstream stream without waiting for later responses. After normal upstream EOF, preserve the existing buffer-drain conditions and then terminate the connection using `abort()`.
- Published-port connections (`src/event_loop/published.rs`): EOF from the external client or namespace service triggers the existing `close_after_drain` logic. Once the existing buffer-drain conditions are met, terminate the entire connection without waiting for future responses from the other direction.

Code changes, refactors, and reviews must respect this policy:

- RSTs during this closure process and the inability to receive later responses after a half-close are expected behaviors accepted by the user. Do not report these behaviors alone as defects.
- Unless the user explicitly changes this requirement, do not introduce independent per-direction closure states, FIN propagation, or half-close support for either forwarding path.
- Preserve the existing buffer-drain conditions. This policy applies only to closure semantics. Other data integrity issues, such as losing prefetched tunnel data after an HTTP CONNECT response, remain subject to normal review.
