from pathlib import Path

GUIDE = Path(__file__).resolve().parents[3] / "docs/helper-configuration.md"


def test_helper_overview_separates_the_ssh_read_catalogue_from_diagnostics_and_config_read():
    text = GUIDE.read_text(encoding="utf-8")
    paragraph = text.split("## Helper capability overview", 1)[1].split("\n\n", 2)[1]
    assert "`ssh_read` catalogue" in paragraph
    assert "`fortios_diagnostics`" in paragraph
    assert "`config_read`" in paragraph
