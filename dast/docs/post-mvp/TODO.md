# MVP 이후 고려사항

## 1. Report Agent 권한 축소

- **현재**: Report Agent가 `_run_attack_agent()`로 실행 → `--enable shell_tool` + `--sandbox none`
- **문제**: Report는 curl을 안 쓰고 글만 쓰는데 shell/네트워크 권한이 열려있음
- **개선**: `_run_structured()`(shell 비활성, sandbox read-only)로 변경

## 2. 플랫폼별 Report SKILL.md

- **현재**: 범용 보고서 SKILL.md 1개
- **개선**: Scope.md에 플랫폼 정보가 이미 있으므로, SKILL.md에 "플랫폼에 맞춰 작성하라"는 지침 추가
- 필요시 `skills/report/hackerone/SKILL.md`, `skills/report/bugcrowd/SKILL.md` 등 분리

## 3. IDOR SKILL.md 공격 범위 확장

- POST/PUT/DELETE 메서드 지원
- 중첩 리소스 (`/users/:id/orders/:id`)
- 파라미터 위치별 처리 (path, query, body, header)
- ID 획득 방법 다양화 (sequential, UUID 추측 등)

## 4. IDOR 외 취약점 유형 추가

- BOLA (Broken Object Level Authorization)
- BFLA (Broken Function Level Authorization)
- Mass Assignment
- 각 유형별 SKILL.md 추가
