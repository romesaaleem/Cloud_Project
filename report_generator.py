from fpdf import FPDF

class ReportGenerator:
    @staticmethod
    def build_pdf(data_list, output_path):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 15, "STAR SHIELD AI INCIDENT REPORT", ln=True, align="C")
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 10, "Generated via STAR Shield SIEM Compliance Processing", ln=True, align="C")
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(15, 8, "ID", border=1, align="C")
        pdf.cell(45, 8, "Timestamp", border=1, align="C")
        pdf.cell(50, 8, "Threat Type", border=1, align="C")
        pdf.cell(25, 8, "Severity", border=1, align="C")
        pdf.cell(25, 8, "Risk Score", border=1, align="C")
        pdf.cell(30, 8, "Status", border=1, align="C")
        pdf.ln()
        pdf.set_font("Helvetica", "", 9)
        for row in data_list:
            pdf.cell(15, 8, str(row["Alert ID"]), border=1, align="C")
            pdf.cell(45, 8, str(row["Timestamp"]), border=1, align="C")
            pdf.cell(50, 8, str(row["Threat Type"]), border=1)
            pdf.cell(25, 8, str(row["Severity"]), border=1, align="C")
            pdf.cell(25, 8, str(row["Risk Score"]), border=1, align="C")
            pdf.cell(30, 8, str(row["Status"]), border=1, align="C")
            pdf.ln()
        pdf.output(output_path)