# tests/test_robots.py
"""
robots.txt parsing is on the roadmap but not yet implemented.

Replace these stubs with real tests once parse_robots() is added
to SecurityScanner (Tier 3, item 3.2).
"""

import pytest


@pytest.mark.skip(reason="not yet implemented - see roadmap 3.2")
def test_robots_disallow_paths_extracted():
    """parse_robots() should return a list of Disallow paths."""
    pass


@pytest.mark.skip(reason="not yet implemented - see roadmap 3.2")
def test_robots_sitemap_extracted():
    """parse_robots() should return Sitemap URLs from robots.txt."""
    pass


@pytest.mark.skip(reason="not yet implemented - see roadmap 3.2")
def test_robots_missing_file_handled_gracefully():
    """parse_robots() returns empty results when robots.txt is missing."""
    pass
