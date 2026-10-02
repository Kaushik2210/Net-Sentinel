/** Global CRT texture: scanlines, vignette and film grain. Purely decorative. */
export function ScanlineOverlay() {
  return (
    <>
      <div className="crt-overlay" aria-hidden />
      <div className="crt-grain" aria-hidden />
    </>
  );
}
