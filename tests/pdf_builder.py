"""
Generador minimo de PDFs sinteticos para pruebas (HU-07), sin depender de
librerias de autoria de PDF (reportlab, etc.) que no forman parte de las
dependencias del proyecto. Construye a mano los objetos PDF, el stream de
contenido con operadores de texto (Tj) y una tabla xref valida.
"""


def build_pdf(page_texts):
    """
    Construye un PDF de una o mas paginas, cada una con una linea de texto
    visible (operador Tj). page_texts: lista de strings, una por pagina.
    """
    num_pages = len(page_texts)
    font_obj_num = 3
    first_page_obj_num = 4  # cada pagina ocupa 2 numeros de objeto: Page y Contents

    page_obj_nums = []
    content_obj_nums = []
    for i in range(num_pages):
        page_obj_nums.append(first_page_obj_num + i * 2)
        content_obj_nums.append(first_page_obj_num + i * 2 + 1)

    kids = " ".join(f"{n} 0 R" for n in page_obj_nums)

    objects_by_num = {}
    objects_by_num[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects_by_num[2] = f"<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>".encode("ascii")
    objects_by_num[font_obj_num] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    for i, text in enumerate(page_texts):
        page_num = page_obj_nums[i]
        content_num = content_obj_nums[i]
        objects_by_num[page_num] = (
            f"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 {font_obj_num} 0 R >> >> "
            f"/MediaBox [0 0 612 792] /Contents {content_num} 0 R >>"
        ).encode("ascii")

        content = f"BT /F1 12 Tf 72 712 Td ({text}) Tj ET".encode("latin1")
        objects_by_num[content_num] = (
            f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream"
        )

    max_obj_num = max(objects_by_num.keys())

    out = bytearray()
    out += b"%PDF-1.4\n"
    offsets = {}
    for obj_num in range(1, max_obj_num + 1):
        if obj_num not in objects_by_num:
            continue
        offsets[obj_num] = len(out)
        out += f"{obj_num} 0 obj\n".encode("ascii")
        out += objects_by_num[obj_num]
        out += b"\nendobj\n"

    xref_offset = len(out)
    out += f"xref\n0 {max_obj_num + 1}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for obj_num in range(1, max_obj_num + 1):
        off = offsets.get(obj_num, 0)
        out += f"{off:010d} 00000 n \n".encode("ascii")

    out += b"trailer\n"
    out += f"<< /Size {max_obj_num + 1} /Root 1 0 R >>\n".encode("ascii")
    out += b"startxref\n"
    out += f"{xref_offset}\n".encode("ascii")
    out += b"%%EOF"
    return bytes(out)
