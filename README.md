# WHS4 DAST Project

통합된 AI DAST 구현은 [`recon-attack-pipeline/`](recon-attack-pipeline/)에 있습니다.
이 폴더 하나에 Scope 수집, Recon, Attack, 7-Question + PoC Validation,
HackerOne·Intigriti·Bugcrowd Report 단계와 테스트·설계 문서가 포함됩니다.

## 시작하기

```bash
git clone https://github.com/Oyeonseok/WHS4_DAST_Project.git
cd WHS4_DAST_Project/recon-attack-pipeline
uv sync
uv run aidast --help
```

자세한 설치, 실행, 보안 경계는
[`recon-attack-pipeline/README.md`](recon-attack-pipeline/README.md)를 참고하세요.

로컬 Scope, 브라우저 세션, Recon/Attack/Validation/Report DB와 실행 산출물은
저장소에 커밋하지 않습니다.
