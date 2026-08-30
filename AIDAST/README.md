# AIDAST

> AI Agent-based Dynamic Application Security Testing Framework

AIDAST는 웹 애플리케이션을 대상으로 AI Agent가 **Scope 확인, 정찰, 공격, 검증, 리포팅** 과정을 수행하는 AI 기반 DAST 프로젝트입니다.

현재는 **Pi Agent Harness를 기반으로 AIDAST용 Agent Harness를 구성하고 Scope Agent를 개발하는 단계**입니다.

---

## Overview

기존 DAST는 미리 정의된 규칙과 Payload를 기반으로 웹 애플리케이션을 검사하는 방식이 일반적입니다.

AIDAST는 이러한 방식에서 확장하여 AI Agent가 웹 애플리케이션과 버그바운티 프로그램의 정책 및 상태를 이해하고, 상황에 따라 다음 작업을 결정할 수 있는 구조를 목표로 합니다.

전체적으로 다음과 같은 Agent 구조를 계획하고 있습니다.

```text
Target / Bug Bounty Program
            │
            ▼
      ┌─────────────┐
      │ Main Agent  │
      └──────┬──────┘
             │
             ▼
      ┌─────────────┐
      │ Scope Agent │
      └──────┬──────┘
             │
             ▼
      ┌─────────────┐
      │ Recon Agent │
      └──────┬──────┘
             │
             ▼
     ┌──────────────┐
     │ Attack Agent │
     └──────┬───────┘
            │
            ▼
   ┌──────────────────┐
   │ Validation Agent │
   └────────┬─────────┘
            │
            ▼
     ┌──────────────┐
     │ Report Agent │
     └──────────────┘
```

---

## Project Goals

AIDAST는 다음과 같은 AI 기반 웹 보안 테스트 자동화를 목표로 합니다.

- 버그바운티 프로그램의 Scope 및 정책 수집
- AI Agent 기반 웹 애플리케이션 탐색
- HTTP Request / Response 분석
- Endpoint 및 애플리케이션 구조 파악
- 정찰 결과를 기반으로 한 취약점 공격 가설 생성
- 취약점 테스트 수행
- 발견된 취약점 후보 재검증
- 재현 가능한 취약점에 대한 PoC 생성
- 검증된 취약점에 대한 보고서 생성
- Agent 간 작업 전달
- 전체 스캔 흐름 오케스트레이션

---

## Current Development Status

현재는 전체 AI DAST Pipeline 중 **Agent Harness와 Scope Agent**를 우선 개발하고 있습니다.

### Implemented

- Pi 기반 Agent Harness 구성
- AIDAST 전용 System Prompt
- Scope Agent 정의
- Agent 설정 디렉터리 구성
- Pi Harness 코드의 AIDAST 프로젝트 통합

현재 AIDAST Agent 관련 설정은 다음과 같이 구성되어 있습니다.

```text
.aidast/
└── agent/
    ├── SYSTEM.md
    └── agents/
        └── scopeAgent.md
```

### In Progress

- Scope Agent 동작 구체화
- 버그바운티 프로그램 페이지 탐색
- Scope 관련 페이지 탐색
- In-Scope / Out-of-Scope 정보 수집
- 프로그램 정책 수집
- 테스트 제한사항 수집
- Scope 정보 구조화

### Planned

- Browser Automation 연동
- Recon Agent
- Attack Agent
- Validation Agent
- Report Agent
- HTTP Traffic 수집 및 분석
- Agent 간 작업 전달
- Agent Orchestration
- 스캔 결과 저장 및 관리

---

## Scope Agent

Scope Agent는 실제 보안 테스트를 수행하기 전에 **어디까지 테스트가 허용되는지 확인하는 역할**을 담당합니다.

버그바운티 프로그램 URL이 입력되면 프로그램의 정책 페이지와 Scope 관련 페이지를 탐색하여 필요한 정보를 수집하는 것을 목표로 합니다.

```text
Bug Bounty Program URL
          │
          ▼
     Scope Agent
          │
          ├── Program Policy 확인
          ├── Scope 관련 페이지 탐색
          ├── In-Scope Asset 수집
          ├── Out-of-Scope Asset 수집
          ├── 테스트 제한사항 확인
          └── Scope 정보 구조화
```

Scope Agent는 단순히 특정 HTML Selector를 이용해 정보를 가져오는 방식이 아니라, Browser Automation 도구와 Agent를 결합하여 페이지의 구조와 내용을 동적으로 판단하면서 필요한 Scope 정보를 탐색하는 방향으로 개발하고 있습니다.

예를 들어 하나의 프로그램 페이지에서 Scope 정보가 모두 제공되지 않는 경우, Agent가 관련 페이지를 추가로 탐색하여 필요한 정책과 Scope 정보를 수집하는 구조를 목표로 합니다.

---

## Planned Agent Architecture

### Main Agent

AIDAST 전체 스캔 흐름을 관리하는 상위 Agent입니다.

각 Agent에게 역할과 작업을 전달하고, Agent가 반환한 결과를 확인한 뒤 다음 단계의 실행 여부를 결정하는 역할을 담당합니다.

예상 흐름은 다음과 같습니다.

```text
Main Agent
    │
    ├── Scope Agent 실행
    │
    ├── Recon Agent 실행
    │
    ├── Attack Agent 실행
    │
    ├── Validation Agent 실행
    │
    └── Report Agent 실행
```

---

### Scope Agent

버그바운티 프로그램 또는 대상 서비스의 정책을 확인하고 테스트 가능한 범위를 수집합니다.

주요 수집 대상은 다음과 같습니다.

- In-Scope Asset
- Out-of-Scope Asset
- Program Policy
- Testing Restrictions
- Automation Restrictions
- Rate Limit 관련 정책
- 기타 테스트 제한사항

---

### Recon Agent

웹 애플리케이션을 탐색하고 공격에 필요한 정보를 수집하는 역할을 담당할 예정입니다.

향후 다음과 같은 기능과 연동할 계획입니다.

- Browser Automation
- Endpoint Discovery
- HTTP Traffic Collection
- Request / Response 분석
- Parameter 수집
- 웹 애플리케이션 구조 분석
- 인증 상태 및 사용자 흐름 분석

Recon Agent가 수집한 결과는 이후 Attack Agent가 취약점 가설을 생성하는 데 활용될 예정입니다.

---

### Attack Agent

Recon Agent가 수집한 정보를 기반으로 취약점 가설을 생성하고 실제 테스트를 수행하는 역할을 담당할 예정입니다.

단순히 모든 Payload를 무작위로 전송하는 방식이 아니라, Recon 결과와 애플리케이션 상태를 기반으로 테스트할 취약점과 대상을 결정하는 구조를 목표로 합니다.

---

### Validation Agent

Attack Agent가 발견한 취약점 후보가 실제 취약점인지 다시 검증하는 역할을 담당할 예정입니다.

Validation Agent는 재현 가능성과 실제 보안 영향을 확인하고, 검증된 결과만 최종 취약점으로 전달하는 구조를 목표로 합니다.

---

### Report Agent

Validation Agent를 통과한 취약점에 대해 최종 보고서를 생성하는 역할을 담당할 예정입니다.

보고서에는 다음과 같은 정보가 포함될 수 있습니다.

- Vulnerability Summary
- Vulnerability Type
- Affected Asset
- Affected Endpoint
- Steps to Reproduce
- PoC
- Request / Response Evidence
- Security Impact
- Additional Evidence

---

## Project Structure

현재 주요 프로젝트 구조는 다음과 같습니다.

```text
AIDAST/
├── .aidast/
│   └── agent/
│       ├── SYSTEM.md
│       └── agents/
│           └── scopeAgent.md
│
├── packages/
│   ├── agent/
│   ├── ai/
│   ├── client/
│   ├── coding-agent/
│   ├── evals/
│   ├── protocol/
│   ├── server/
│   ├── session-backends/
│   ├── telemetry/
│   └── tui/
│
├── scripts/
├── package.json
├── package-lock.json
├── tsconfig.json
└── README.md
```

현재 `packages/`를 포함한 Agent Harness 기반 코드는 Pi 프로젝트를 기반으로 하며, AIDAST에 필요한 기능을 추가하고 수정하는 방향으로 개발하고 있습니다.

---

## Agent Configuration

AIDAST에서 사용하는 Agent 관련 설정은 `.aidast/agent` 디렉터리에 위치합니다.

```text
.aidast/
└── agent/
    ├── SYSTEM.md
    └── agents/
        └── scopeAgent.md
```

### SYSTEM.md

AIDAST Agent가 기본적으로 따라야 하는 시스템 수준의 역할과 동작 방식을 정의합니다.

### scopeAgent.md

Scope Agent의 역할과 작업 범위를 정의합니다.

현재 Scope Agent는 AIDAST에서 가장 먼저 개발되고 있는 하위 Agent입니다.

---

## Development

### Requirements

- Node.js
- npm

### Install Dependencies

```bash
npm install --ignore-scripts
```

### Build

```bash
npm run build
```

### Offline Build

```bash
npm run build:offline
```

### Check

```bash
npm run check
```

현재 Pi 기반 개발 환경을 사용하고 있으며, 개발이 진행됨에 따라 AIDAST 전용 실행 방식과 설정으로 변경될 수 있습니다.

---

## Development Roadmap

```text
Pi Agent Harness
       │
       ▼
AIDAST Agent Harness
       │
       ▼
   Scope Agent
       │
       ▼
Browser / Scope Collection
       │
       ▼
   Recon Agent
       │
       ▼
  Attack Agent
       │
       ▼
Validation Agent
       │
       ▼
  Report Agent
       │
       ▼
 AI DAST Pipeline
```

현재는 전체 AI DAST 기능을 한 번에 구현하지 않고, Agent Harness와 Scope Agent부터 단계적으로 개발하고 있습니다.

---

## Security Notice

AIDAST는 웹 애플리케이션 보안 테스트 및 버그바운티 환경에서의 사용을 목적으로 개발되고 있습니다.

본인이 소유하거나 **명시적으로 테스트 권한을 받은 시스템에서만 사용해야 합니다.**

버그바운티 프로그램에서 사용하는 경우 반드시 해당 프로그램에서 정의한 정책을 준수해야 합니다.

예를 들어 다음과 같은 제한사항을 확인해야 합니다.

- In-Scope / Out-of-Scope
- Program Policy
- Automation Policy
- Testing Restrictions
- Rate Limit
- DoS 관련 제한
- 사용자 데이터 접근 관련 제한
- 기타 프로그램별 테스트 정책

AIDAST의 Scope Agent는 이러한 정책을 수집하고 이후 Agent가 허용된 범위 안에서 동작할 수 있도록 하는 것을 목표로 합니다.

---

## Acknowledgements

AIDAST is based on and modifies code from the Pi agent harness.

- Original project: https://github.com/earendil-works/pi
- Pi is licensed under the MIT License.
- The original license and copyright notices are retained.
- Modifications and additional components were made for the AIDAST project.

We thank the Pi contributors for making the original project available as open source.

---

## License

See [LICENSE](LICENSE) for license information.
