"""
gap_detector.py — CV-based slider gap detection for Tencent captcha.

Uses edge-template matching to locate the puzzle-piece gap in the background image.
The slider image (index=2) is a PNG with alpha channel containing the gap shape.
The background image (index=1) is a JPEG with the gap region.

Detection pipeline:
    1. Load bg (RGB) and slider (RGBA)
    2. Extract visible portion of slider using alpha mask
    3. Edge-detect both images
    4. Template-match slider edges against background edges
    5. Apply empirical offset correction based on HAR validation
    6. Return gap center coordinates (ans)

Validated against urlsec.qq.com.har: edge-match + offset yields ans within ~4px of ground truth.
"""

import cv2
import numpy as np
from typing import Tuple, Optional

# Vendored into browserless_pipeline so the package is self-contained.
# The runtime path uses only detect_gap_multiscale(bg, slider) on already-decoded
# arrays — `requests` is needed only by the optional download_image()/*_from_urls
# helpers, so it is imported lazily there (keeps the hard deps to cv2 + numpy).


# Empirical offset correction derived from HAR analysis:
# Edge template match at (483,70) -> true ans (488,70) in urlsec.qq.com.har.
# The match location is close to the gap's top-left corner.
DEFAULT_X_OFFSET = 5
DEFAULT_Y_OFFSET = 0


def download_image(url: str, headers: Optional[dict] = None) -> np.ndarray:
    """Download image from URL and return as OpenCV BGR(A) array."""
    import requests  # optional dep — only this helper needs it
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    img_array = np.frombuffer(resp.content, dtype=np.uint8)
    # IMREAD_UNCHANGED preserves alpha if present
    img = cv2.imdecode(img_array, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError(f"Failed to decode image from {url}")
    return img


def extract_visible_region(slider: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extract the non-transparent visible region from the slider image.
    
    Args:
        slider: OpenCV array, may be RGB or RGBA
        
    Returns:
        (visible_rgb, mask) where visible_rgb is the cropped RGB region
        and mask is the binary alpha mask for that region.
    """
    if slider.ndim == 3 and slider.shape[2] == 4:
        b, g, r, a = cv2.split(slider)
        rgb = cv2.merge([b, g, r])
        mask = (a > 128).astype(np.uint8) * 255
    else:
        rgb = slider
        mask = np.ones((slider.shape[0], slider.shape[1]), dtype=np.uint8) * 255

    # Find bounding box of non-transparent pixels
    non_zero = cv2.findNonZero(mask)
    if non_zero is None:
        return rgb, mask

    x, y, w, h = cv2.boundingRect(non_zero)
    visible_rgb = rgb[y:y+h, x:x+w]
    visible_mask = mask[y:y+h, x:x+w]
    return visible_rgb, visible_mask


def detect_gap(
    bg: np.ndarray,
    slider: np.ndarray,
    canny_low: int = 50,
    canny_high: int = 150,
    x_offset: int = DEFAULT_X_OFFSET,
    y_offset: int = DEFAULT_Y_OFFSET,
) -> Tuple[int, int, float]:
    """
    Detect the gap position using edge-based template matching.
    
    Uses the FULL slider image (including transparent border) because the
    boundary between visible and transparent regions contributes strong edge
    features that improve match accuracy vs. HAR ground truth.
    
    Args:
        bg: Background image (BGR, any size, typically 680x390)
        slider: Slider/puzzle piece image (BGR or BGRA, typically 136x136)
        canny_low: Lower threshold for Canny edge detector
        canny_high: Upper threshold for Canny edge detector
        x_offset: Empirical x offset to add to match location
        y_offset: Empirical y offset to add to match location
        
    Returns:
        (gap_x, gap_y, confidence) where (gap_x, gap_y) is the estimated
        gap center coordinate for the ans parameter, and confidence is
        the template-match correlation score.
    """
    if slider.ndim == 3 and slider.shape[2] == 4:
        b, g, r, a = cv2.split(slider)
        slider_rgb = cv2.merge([b, g, r])
        mask = (a > 128).astype(np.uint8) * 255
    else:
        slider_rgb = slider
        mask = np.ones((slider.shape[0], slider.shape[1]), dtype=np.uint8) * 255

    # Edge detection on FULL slider image, then mask
    bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    bg_edges = cv2.Canny(bg_gray, canny_low, canny_high)

    slider_gray = cv2.cvtColor(slider_rgb, cv2.COLOR_BGR2GRAY)
    slider_edges = cv2.Canny(slider_gray, canny_low, canny_high)
    slider_edges_masked = cv2.bitwise_and(slider_edges, slider_edges, mask=mask)

    # Template matching using normalized correlation coefficient on edges
    result = cv2.matchTemplate(bg_edges, slider_edges_masked, cv2.TM_CCOEFF_NORMED)
    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)

    match_x, match_y = max_loc

    # Based on HAR validation (ans=488,70 vs match=483,70), the match location
    # is close to the gap's top-left corner. We add offsets to approximate the
    # actual ans coordinate expected by the server.
    gap_x = match_x + x_offset
    gap_y = match_y + y_offset

    return gap_x, gap_y, max_val


def detect_gap_multiscale(
    bg: np.ndarray,
    slider: np.ndarray,
    scales: Tuple[float, ...] = (0.9, 1.0, 1.1),
) -> Tuple[int, int, float]:
    """
    Multi-scale gap detection for robustness against image resizing.
    
    Args:
        bg: Background image
        slider: Slider image
        scales: Scale factors to try on the slider image
        
    Returns:
        (gap_x, gap_y, confidence) of the best match across all scales.
    """
    best_conf = -1.0
    best_xy = (0, 0)

    for scale in scales:
        if scale == 1.0:
            slider_scaled = slider
        else:
            new_w = int(slider.shape[1] * scale)
            new_h = int(slider.shape[0] * scale)
            slider_scaled = cv2.resize(slider, (new_w, new_h), interpolation=cv2.INTER_AREA)

        gx, gy, conf = detect_gap(bg, slider_scaled)
        if conf > best_conf:
            best_conf = conf
            best_xy = (gx, gy)

    return best_xy[0], best_xy[1], best_conf


def detect_gap_from_urls(
    bg_url: str,
    slider_url: str,
    headers: Optional[dict] = None,
    multiscale: bool = True,
) -> Tuple[int, int, float]:
    """
    Convenience wrapper: download images from URLs and detect gap.
    
    Args:
        bg_url: URL of background image (hycdn?index=1)
        slider_url: URL of slider image (hycdn?index=2)
        headers: Optional HTTP headers
        multiscale: Whether to try multiple scales
        
    Returns:
        (gap_x, gap_y, confidence)
    """
    bg = download_image(bg_url, headers)
    slider = download_image(slider_url, headers)

    if multiscale:
        return detect_gap_multiscale(bg, slider)
    return detect_gap(bg, slider)


if __name__ == "__main__":
    # Quick test with local HAR images if available
    import sys
    if len(sys.argv) >= 3:
        bg_path = sys.argv[1]
        slider_path = sys.argv[2]
        bg = cv2.imread(bg_path)
        slider = cv2.imread(slider_path, cv2.IMREAD_UNCHANGED)
        x, y, conf = detect_gap(bg, slider)
        print(f"Detected gap: x={x}, y={y}, confidence={conf:.4f}")
    else:
        print("Usage: python gap_detector.py <bg_image> <slider_image>")
