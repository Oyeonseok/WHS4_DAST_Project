# AIDAST

AI Agent-based Dynamic Application Security Testing framework.

AIDAST는 웹 애플리케이션을 대상으로 스코프 수집, 정찰, 공격,
검증 및 리포팅 과정을 AI Agent 기반으로 자동화하기 위한 프로젝트입니다.

## Current Status

현재 Pi Agent Harness를 기반으로 AIDAST용 Agent Harness를 구성하고 있으며,
Scope Agent를 우선 구현하고 있습니다.

## Architecture

Main Agent
├── Scope Agent
├── Recon Agent
├── Attack Agent
├── Validation Agent
└── Report Agent

## Current Implementation

- Pi 기반 Agent Harness
- AIDAST System Prompt
- Scope Agent
- 향후 Playwright / browser automation 연동 예정

## Project Structure

AIDAST/
├── .aidast/
│   └── agent/
│       ├── SYSTEM.md
│       └── agents/
│           └── scopeAgent.md
├── packages/
├── scripts/
└── ...

## Development

(여기에 실행 방법 작성)

## Acknowledgements

This project is based on and modifies code from the Pi agent harness.

- Original project: https://github.com/earendil-works/pi
- Pi is licensed under the MIT License.
- The original license and copyright notices are retained.
- Modifications and additional components were made for the AIDAST project.

## License

See [LICENSE](LICENSE).
