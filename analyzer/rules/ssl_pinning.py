# -*- coding: utf-8 -*-
"""
HTTPS 证书固定 (SSL/TLS Pinning) 检测规则库
覆盖主流第三方框架 (TrustKit, AFNetworking, Alamofire)、底层 Security.framework API 与 OpenSSL/BoringSSL 自定义校验
"""

from typing import List, Dict, Any
from .base import RuleCategory, Severity


SSL_PINNING_RULES: List[Dict[str, Any]] = [
    {
        "id": "SSL-001",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.CRITICAL,
        "title": "TrustKit 证书与公钥固定框架",
        "description": "应用集成了 TrustKit 框架，通过配置公钥哈希 (SPKI SHA-256 Hashes) 进行强制 SSL Pinning，自动拦截原生网络请求的 SSL 握手。",
        "remediation": "使用 Frida Hook `-[TrustKit initSharedInstanceWithConfiguration:]` 或 Hook `-[TSKPinningValidator evaluateTrust:forHostname:]` 返回 TSKTrustEvaluationSuccess (0)；或利用通用脚本 SSL Kill Switch 2。",
        "patterns": {
            "strings": [
                "TrustKit",
                "TSKPinningValidator",
                "TSKPinningValidatorResult",
                "kTSKPublicKeyHashes",
                "kTSKEnforcePinning",
                "kTSKIncludeSubdomains",
                "TSKTrustDecision"
            ],
            "regex": [
                r"\bTrustKit\b",
                r"TSKPinningValidator",
                r"kTSKPublicKeyHashes"
            ]
        }
    },
    {
        "id": "SSL-002",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.CRITICAL,
        "title": "AFNetworking / AFSecurityPolicy 证书策略配置",
        "description": "应用使用 AFNetworking 网络库并通过 AFSecurityPolicy 设置了证书绑定模式 (AFSSLPinningModeCertificate 或 AFSSLPinningModePublicKey)。",
        "remediation": "使用 Frida Hook `-[AFSecurityPolicy evaluateServerTrust:forDomain:]` 直接返回 YES (True)，或 Hook `+[AFSecurityPolicy defaultPolicy]` 将 `SSLPinningMode` 置为 0 (AFSSLPinningModeNone)。",
        "patterns": {
            "strings": [
                "AFSecurityPolicy",
                "setPinnedCertificates:",
                "setSSLPinningMode:",
                "evaluateServerTrust:forDomain:",
                "pinnedCertificates",
                "allowInvalidCertificates"
            ],
            "regex": [
                r"AFSecurityPolicy",
                r"evaluateServerTrust:\s*forDomain:",
                r"setSSLPinningMode:"
            ]
        }
    },
    {
        "id": "SSL-003",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.CRITICAL,
        "title": "Alamofire (Swift) ServerTrustManager 证书评估器",
        "description": "应用使用 Swift Alamofire 框架，并配置了 PinnedCertificatesTrustEvaluator 或 PublicKeysTrustEvaluator 进行自定义证书/公钥比对校验。",
        "remediation": "Hook `ServerTrustManager` 或针对 `ServerTrustEvaluating` 协议的 `evaluate(trust:forHost:)` 方法强制通过校验。",
        "patterns": {
            "strings": [
                "ServerTrustManager",
                "PinnedCertificatesTrustEvaluator",
                "PublicKeysTrustEvaluator",
                "CompositeTrustEvaluator",
                "ServerTrustEvaluating",
                "DisabledTrustEvaluator"
            ],
            "regex": [
                r"(?:PinnedCertificates|PublicKeys|Composite)TrustEvaluator",
                r"ServerTrustManager"
            ]
        }
    },
    {
        "id": "SSL-004",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.HIGH,
        "title": "底层 Security.framework 证书信任链自定义评估 (SecTrust)",
        "description": "调用 Security.framework 原生 API（如 SecTrustEvaluate, SecTrustEvaluateWithError, SecTrustSetAnchorCertificates 等）进行自定义根证书或证书公钥提取对比。",
        "remediation": "Hook `SecTrustEvaluateWithError`（iOS 12+）使其总是返回 true 并将 error 设置为 NULL；Hook `SecTrustEvaluate` 将 result 设为 kSecTrustResultProceed / kSecTrustResultUnspecified 并返回 errSecSuccess (0)。",
        "patterns": {
            "imports": [
                "_SecTrustEvaluate", "SecTrustEvaluate",
                "_SecTrustEvaluateWithError", "SecTrustEvaluateWithError",
                "_SecTrustSetAnchorCertificates", "SecTrustSetAnchorCertificates",
                "_SecTrustSetAnchorCertificatesOnly", "SecTrustSetAnchorCertificatesOnly",
                "_SecTrustCopyCustomAnchorCertificates", "SecTrustCopyCustomAnchorCertificates",
                "_SecCertificateCreateWithData", "SecCertificateCreateWithData",
                "_SecTrustGetCertificateAtIndex", "SecTrustGetCertificateAtIndex"
            ],
            "symbols": [
                "_SecTrustEvaluate", "SecTrustEvaluate",
                "_SecTrustEvaluateWithError", "SecTrustEvaluateWithError",
                "_SecTrustSetAnchorCertificates", "SecTrustSetAnchorCertificates"
            ],
            "strings": [
                "SecTrustEvaluate",
                "SecTrustEvaluateWithError",
                "SecTrustSetAnchorCertificates",
                "SecTrustCopyCustomAnchorCertificates"
            ],
            "regex": [
                r"SecTrustEvaluate(?:WithError)?",
                r"SecTrustSetAnchorCertificates(?:Only)?"
            ]
        }
    },
    {
        "id": "SSL-005",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.HIGH,
        "title": "NSURLSession / NSURLConnection 认证挑战委托实现",
        "description": "实现了 NSURLSessionDelegate 的 didReceiveChallenge 认证挑战回调，通常用于在客户端收到服务器证书时拦截并进行证书指纹比对。",
        "remediation": "Hook 对应 Delegate 类的 `URLSession:didReceiveChallenge:completionHandler:`，直接调用 completionHandler 回调 `NSURLSessionAuthChallengeUseCredential` 与系统默认凭证。",
        "patterns": {
            "strings": [
                "URLSession:didReceiveChallenge:completionHandler:",
                "URLSession:task:didReceiveChallenge:completionHandler:",
                "connection:willSendRequestForAuthenticationChallenge:",
                "NSURLAuthenticationMethodServerTrust"
            ],
            "regex": [
                r"URLSession:(?:task:)?didReceiveChallenge:completionHandler:",
                r"NSURLAuthenticationMethodServerTrust"
            ]
        }
    },
    {
        "id": "SSL-006",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.MEDIUM,
        "title": "BoringSSL / OpenSSL 自定义证书校验回调",
        "description": "应用或依赖库内嵌了 BoringSSL / OpenSSL，通过设置 SSL_CTX_set_custom_verify 或 SSL_set_custom_verify 绕过系统层并实施私有证书链或公钥校验（常见于 Flutter, gRPC, Chromium 网络栈）。",
        "remediation": "在动态分析时针对 Flutter Engine / BoringSSL 中的 `SSL_CTX_set_custom_verify` 回调函数地址进行 Hook，将验证状态直接返回 0 (ssl_verify_ok)。",
        "patterns": {
            "symbols": [
                "SSL_CTX_set_custom_verify",
                "SSL_set_custom_verify",
                "custom_verify_callback",
                "X509_verify_cert"
            ],
            "strings": [
                "SSL_CTX_set_custom_verify",
                "SSL_set_custom_verify",
                "ssl_verify_result_t",
                "custom_verify_callback",
                "BORINGSSL_bssl_sys"
            ],
            "regex": [
                r"SSL(?:_CTX)?_set_custom_verify",
                r"ssl_verify_result_t"
            ]
        }
    },
    {
        "id": "SSL-007",
        "category": RuleCategory.SSL_PINNING,
        "severity": Severity.INFO,
        "title": "应用包内包含预埋证书文件 (Bundled Certificate Assets)",
        "description": "在 App Bundle 或 Frameworks 资源目录中发现了 .cer/.crt/.der/.pem 证书文件，通常作为证书固定对比的本地锚点或自定义 CA。",
        "remediation": "可从 IPA 包中提取这些证书文件分析其公钥哈希与过期时间，配合抓包工具自建证书或直接在内存中替换这些证书对象。",
        "patterns": {
            "file_exts": [".cer", ".crt", ".der", ".pem", ".p12", ".pfx"]
        }
    }
]
