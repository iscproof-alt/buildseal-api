import json, sys
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm

def generate_pdf(pack_path):
    with open(pack_path) as f:
        pack = json.load(f)
    output = pack_path.replace(".json", "_proof.pdf")
    doc = SimpleDocTemplate(output, pagesize=A4)
    story = []
    t1 = ParagraphStyle("t", fontSize=20, fontName="Helvetica-Bold", spaceAfter=20)
    story.append(Paragraph("ISCProof Seal Certificate", t1))
    story.append(Spacer(1, 0.5*cm))
    ch = pack.get("content_hash", {}).get("digest", "")
    data = [
        ["Version", str(pack.get("version", ""))],
        ["Profile", pack.get("profile", "")],
        ["Content ID", pack.get("content_id", "")],
        ["Sealed At", pack.get("sealed_at", "")],
        ["Root", pack.get("root", "")[:40]],
        ["Parent", pack.get("parent", "") or "genesis"],
        ["Hash", ch[:40]],
    ]
    t = Table(data, colWidths=[4*cm, 13*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#1F3864")),
        ("TEXTCOLOR", (0,0), (0,-1), colors.white),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("PADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    doc.build(story)
    print("PDF created:", output)

generate_pdf(sys.argv[1])
