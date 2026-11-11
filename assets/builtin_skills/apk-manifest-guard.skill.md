---
skill_id: "apk-manifest-guard"
name: "Android APK & Manifest Security Guard"
tier: "default"
target_languages: ["kotlin", "java", "xml"]
trigger_conditions:
  manifest_files: ["AndroidManifest.xml"]
  component_types: ["activity", "service", "receiver", "provider"]
required_mcp_tools: ["audit_manifest", "trace_intent_filters"]
---

# Android APK & Manifest Security Guard

## 1. Exported Component Audit
1. Check all `<activity>`, `<service>`, and `<receiver>` components for `android:exported="true"`.
2. Ensure components with intent filters define explicit permission guards.
3. Verify that `android:debuggable` is omitted or set to `false` for release builds.

## 2. Remediation Strategy
Explicitly set `android:exported="false"` on internal components and apply strict signature-level permissions.
