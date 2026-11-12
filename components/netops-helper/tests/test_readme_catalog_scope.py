from pathlib import Path

README = Path(__file__).resolve().parents[3] / "README.md"


def test_readme_separates_the_ssh_read_catalogue_from_diagnostics_and_config_read():
    text = README.read_text(encoding="utf-8")
    paragraph = text.split("### Helper — read-only diagnostics", 1)[1].split("\n\n", 2)[1]
    assert "`ssh_read` catalogue" in paragraph
    assert "`fortios_diagnostics`" in paragraph
    assert "`config_read`" in paragraph
