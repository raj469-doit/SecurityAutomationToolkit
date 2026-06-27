# tests/test_robots.py
"""
robots.txt parsing is on the roadmap but not yet implemented.

This file is a placeholder. Once parse_robots() is added to SecurityScanner
(Tier 3, item 3.2), replace these stubs with real tests.
"""

import pytest


@pytest.mark.skip(reason="robots.txt parsing not yet implemented (see roadmap item 3.2)")
def test_robots_disallow_paths_extracted():
    """parse_robots() should return a list of Disallow paths."""
    pass


@pytest.mark.skip(reason="robots.txt parsing not yet implemented (see roadmap item 3.2)")
def test_robots_sitemap_extracted():
    """parse_robots() should return Sitemap URLs found in robots.txt."""
    pass


@pytest.mark.skip(reason="robots.txt parsing not yet implemented (see roadmap item 3.2)")
def test_robots_missing_file_handled_gracefully():
    """parse_robots() should return empty results when /robots.txt returns 404."""
    pass
