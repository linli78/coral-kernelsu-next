# coral-kernelsu-next

Cloud build scaffold for a Google Pixel 4 XL (coral) Android 13 kernel with KernelSU Next.

Target:
- Device: Pixel 4 XL (coral)
- Android build: TP1A.220624.014
- Stock kernel observed on device: 4.14.276-g8ae7b4ca8564-ab8715030
- Google kernel branch: android-msm-coral-4.14-android13

The workflow is intentionally conservative:
- uses Google's official legacy Pixel kernel branch
- integrates KernelSU Next in legacy mode
- pins KernelSU Next to a fixed legacy revision
- uploads build outputs as GitHub Actions artifacts

Important: always test any resulting boot image with `fastboot boot` before flashing permanently.
