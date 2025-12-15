"""
Screenshot capture service for web services using Playwright.
"""
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import asyncio
import logging

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from sqlalchemy.orm import Session

from icebreaker.db.models import Screenshot, Service, Scan

logger = logging.getLogger(__name__)


class ScreenshotService:
    """Service for capturing screenshots of web services."""

    def __init__(self, output_dir: str = "screenshots"):
        """
        Initialize the screenshot service.

        Args:
            output_dir: Directory to store screenshots
        """
        # Use absolute path to avoid issues in Docker
        if not Path(output_dir).is_absolute():
            self.output_dir = Path.cwd() / output_dir
        else:
            self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def capture_screenshot(
        self,
        url: str,
        service_id: int,
        scan_id: int,
        db: Session,
        timeout: int = 30000
    ) -> Optional[Screenshot]:
        """
        Capture a screenshot of a web service.

        Args:
            url: URL to capture
            service_id: Database ID of the service
            scan_id: Database ID of the scan
            db: Database session
            timeout: Timeout in milliseconds

        Returns:
            Screenshot object if successful, None otherwise
        """
        screenshot_record = Screenshot(
            service_id=service_id,
            scan_id=scan_id,
            url=url,
            screenshot_path="",
            capture_status="pending"
        )
        db.add(screenshot_record)
        db.commit()
        db.refresh(screenshot_record)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    ignore_https_errors=True,
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                )
                page = await context.new_page()

                # Set up response handler to capture metadata
                response_data = {}

                async def handle_response(response):
                    if response.url == url:
                        response_data['status_code'] = response.status
                        response_data['headers'] = dict(response.headers)
                        response_data['content_type'] = response.headers.get('content-type', '')

                page.on('response', handle_response)

                # Navigate to the URL
                try:
                    await page.goto(url, timeout=timeout, wait_until='networkidle')
                except PlaywrightTimeout:
                    logger.warning(f"Timeout loading {url}, continuing anyway...")
                    # Continue anyway, we might have partial content

                # Get page title
                page_title = await page.title()

                # Detect technologies from headers and page content
                technologies = await self._detect_technologies(page, response_data.get('headers', {}))

                # Generate screenshot filename
                screenshot_filename = f"screenshot_{scan_id}_{service_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
                screenshot_path = self.output_dir / screenshot_filename

                # Capture screenshot
                await page.screenshot(path=str(screenshot_path), full_page=True)

                await browser.close()

                # Update screenshot record
                # Store relative path for portability
                try:
                    rel_path = screenshot_path.relative_to(Path.cwd())
                    screenshot_record.screenshot_path = str(rel_path)
                except ValueError:
                    # If can't get relative path, store absolute path
                    screenshot_record.screenshot_path = str(screenshot_path)
                screenshot_record.page_title = page_title[:500] if page_title else None
                screenshot_record.status_code = response_data.get('status_code')
                screenshot_record.content_type = response_data.get('content_type', '')[:100]
                screenshot_record.headers = response_data.get('headers', {})
                screenshot_record.technologies = technologies
                screenshot_record.capture_status = "success"
                screenshot_record.captured_at = datetime.utcnow()
                screenshot_record.error_message = None

                db.commit()
                db.refresh(screenshot_record)

                logger.info(f"Successfully captured screenshot for {url}")
                return screenshot_record

        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {str(e)}")
            screenshot_record.capture_status = "failed"
            screenshot_record.error_message = str(e)[:1000]
            db.commit()
            return None

    async def _detect_technologies(self, page, headers: Dict[str, str]) -> list:
        """
        Detect web technologies from page content and headers.

        Args:
            page: Playwright page object
            headers: HTTP response headers

        Returns:
            List of detected technologies
        """
        technologies = []

        # Check headers for common technologies
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'iis' in server:
            technologies.append('IIS')

        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')

        # Check for common frameworks in page content
        try:
            content = await page.content()
            content_lower = content.lower()

            # JavaScript frameworks
            if 'react' in content_lower or '_react' in content_lower:
                technologies.append('React')
            if 'vue' in content_lower or 'vue.js' in content_lower:
                technologies.append('Vue.js')
            if 'angular' in content_lower:
                technologies.append('Angular')
            if 'jquery' in content_lower:
                technologies.append('jQuery')

            # CMS
            if 'wp-content' in content_lower or 'wordpress' in content_lower:
                technologies.append('WordPress')
            if 'drupal' in content_lower:
                technologies.append('Drupal')
            if 'joomla' in content_lower:
                technologies.append('Joomla')

            # CSS frameworks
            if 'bootstrap' in content_lower:
                technologies.append('Bootstrap')
            if 'tailwind' in content_lower:
                technologies.append('Tailwind CSS')

        except Exception as e:
            logger.warning(f"Error detecting technologies from content: {str(e)}")

        return list(set(technologies))  # Remove duplicates

    async def capture_service_screenshots(self, scan_id: int, db: Session):
        """
        Capture screenshots for all HTTP/HTTPS services in a scan.

        Args:
            scan_id: Database ID of the scan
            db: Database session
        """
        # Get all services for this scan that are HTTP/HTTPS
        services = db.query(Service).filter(
            Service.scan_id == scan_id,
            Service.name.in_(['http', 'https', 'ssl/http', 'http-proxy', 'https-alt'])
        ).all()

        logger.info(f"Found {len(services)} HTTP/HTTPS services to screenshot for scan {scan_id}")

        for service in services:
            # Determine URL scheme
            if service.name in ['https', 'ssl/http']:
                scheme = 'https'
            else:
                scheme = 'http'

            # Construct URL
            url = f"{scheme}://{service.target}:{service.port}"

            logger.info(f"Capturing screenshot for {url}")
            await self.capture_screenshot(
                url=url,
                service_id=service.id,
                scan_id=scan_id,
                db=db
            )

            # Small delay between captures to avoid overwhelming the target
            await asyncio.sleep(1)

        logger.info(f"Completed screenshot capture for scan {scan_id}")


def capture_screenshots_sync(scan_id: int, db: Session):
    """
    Synchronous wrapper for capturing screenshots.

    Args:
        scan_id: Database ID of the scan
        db: Database session
    """
    service = ScreenshotService()
    asyncio.run(service.capture_service_screenshots(scan_id, db))
