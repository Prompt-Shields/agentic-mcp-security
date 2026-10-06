"""Bundle the list's topic pages into the package, so it runs without a checkout.

From a checkout the pages are in the repository root (this directory's parent).
In an sdist they have already been copied to content/ beside this file.
"""

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if version == "editable":
            return  # an editable install reads the pages from the checkout
        root = Path(self.root)
        pages = sorted(root.parent.glob("mcp_*.md")) or sorted((root / "content").glob("mcp_*.md"))
        if not pages:
            raise RuntimeError("no mcp_*.md topic pages found to bundle")
        dest = "awesome_mcp_security/content" if self.target_name == "wheel" else "content"
        for page in pages:
            build_data["force_include"][str(page)] = f"{dest}/{page.name}"
