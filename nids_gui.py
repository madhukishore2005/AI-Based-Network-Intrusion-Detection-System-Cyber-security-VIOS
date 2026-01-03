import sys, os, time, traceback
import numpy as np
import pandas as pd
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem,
    QMessageBox, QTextEdit, QDialog, QComboBox,
    QInputDialog, QLineEdit
)
from PyQt5.QtCore import QTimer

if not hasattr(QInputDialog, "Password"):
    QInputDialog.Password = QLineEdit.Password

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from openpyxl import Workbook
import joblib

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

# ===================== CONFIG =====================
MODEL_RF = "soc_rf.pkl"
MODEL_IF = "soc_if.pkl"
EXCEL_FILE = "SOC_Incident_Report.xlsx"
EXEC_PDF = "SOC_Executive_Report.pdf"
FEATURES = ["packet","duration","src","dst","fails","rate"]
MAX_POINTS = 20
ADMIN_PIN = "1234"

# ===================== SLA POLICY =====================
SLA_POLICY = {"LOW":60,"MEDIUM":60,"HIGH":40,"CRITICAL":20}
SLA_TRACKER = {}
SLA_STATS = {"MTTD":[], "MTTR":[], "BREACHES":0}

# ===================== LEGAL =====================
DISCLAIMER = (
    "This is a DEFENSIVE cybersecurity system.\n\n"
    "• Simulated traffic only\n"
    "• No packet sniffing\n"
    "• No surveillance\n\n"
    "For lawful educational use only."
)

# ===================== DATA =====================
def traffic():
    return {
        "packet": np.random.randint(100,1400),
        "duration": round(np.random.rand()*5,2),
        "src": np.random.randint(500,9000),
        "dst": np.random.randint(500,9000),
        "fails": np.random.randint(0,3),
        "rate": np.random.randint(10,80)
    }

def train_data(n=5000):
    df = pd.DataFrame([traffic() for _ in range(n)])
    df["label"] = ((df["fails"]>1)|(df["rate"]>60)|(df["packet"]>1200)).astype(int)
    return df

# ===================== ML =====================
def train_models():
    df = train_data()
    rf = RandomForestClassifier(n_estimators=300, max_depth=18, class_weight="balanced")
    rf.fit(df[FEATURES], df["label"])
    iso = IsolationForest(contamination=0.05)
    iso.fit(df[FEATURES])
    joblib.dump(rf, MODEL_RF)
    joblib.dump(iso, MODEL_IF)

def load_models():
    if not os.path.exists(MODEL_RF):
        train_models()
    return joblib.load(MODEL_RF), joblib.load(MODEL_IF)

# ===================== THREAT LOGIC =====================
def risk(r): return min(int(r["fails"]*35+r["rate"]*0.6+r["packet"]*0.04),100)
def severity(s): return "CRITICAL" if s>=85 else "HIGH" if s>=60 else "MEDIUM" if s>=35 else "LOW"
def confidence(s): return min(int(s*1.1),100)
def ai_escalation(s,sev): return min(int((s/100+{"LOW":0.1,"MEDIUM":0.3,"HIGH":0.6,"CRITICAL":0.9}[sev])*100),100)

def threat_type(r):
    if r["fails"]>1: return "Brute Force"
    if r["rate"]>65: return "DoS / Flood"
    if r["packet"]>1200: return "Suspicious Scan"
    return "Anomaly"

MITRE = {"Brute Force":"T1110","DoS / Flood":"T1499","Suspicious Scan":"T1046","Anomaly":"TA0006"}
ISO   = {"Brute Force":"A.16.1","DoS / Flood":"A.13.1","Suspicious Scan":"A.12.4","Anomaly":"A.18.1"}

# ===================== AI COPILOT =====================
class AICopilotDialog(QDialog):
    def __init__(self, notes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SOC AI Copilot")
        self.setGeometry(350,200,600,400)
        layout = QVBoxLayout()
        chat = QTextEdit()
        chat.setReadOnly(True)
        chat.setText(
            "AI SOC Copilot Analysis\n"
            "----------------------\n\n"
            + notes +
            "\n\nRecommended Actions:\n"
            "• Validate\n• Investigate\n• Escalate\n• Close"
        )
        layout.addWidget(chat)
        btn = QPushButton("Close")
        btn.clicked.connect(self.close)
        layout.addWidget(btn)
        self.setLayout(layout)

# ===================== MAIN GUI =====================
class SOCNIDS(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enterprise SOC AI-NIDS")
        self.setGeometry(80,60,1900,950)

        self.rf, self.iso = load_models()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.monitor)

        self.role="Analyst"
        self.alert_rate=[]
        self.severity_count={"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
        self.incident_age={}
        self.role_snapshot={}

        self.build_ui()
        QMessageBox.information(self,"Legal Notice",DISCLAIMER)

    def build_ui(self):
        layout=QVBoxLayout()
        layout.addWidget(QLabel("🛡️ Enterprise SOC AI-NIDS Dashboard"))

        bar=QHBoxLayout()
        bar.addWidget(QLabel("Role:"))
        self.role_box=QComboBox()
        self.role_box.addItems(["Analyst","Admin"])
        self.role_box.currentTextChanged.connect(self.set_role)
        bar.addWidget(self.role_box)
        layout.addLayout(bar)

        charts=QHBoxLayout()
        self.fig_line=Figure(figsize=(5,3))
        self.line_canvas=FigureCanvas(self.fig_line)
        charts.addWidget(self.line_canvas)
        self.fig_pie=Figure(figsize=(6,4))
        self.pie_canvas=FigureCanvas(self.fig_pie)
        charts.addWidget(self.pie_canvas)
        layout.addLayout(charts)

        self.table=QTableWidget(0,12)
        self.table.setHorizontalHeaderLabels([
            "Time","Threat","Risk","Severity","Confidence",
            "Status","Role","Owner","Notes","MITRE","ISO","AI Escalation %"
        ])
        layout.addWidget(self.table)

        btns=QHBoxLayout()
        self.start_btn=QPushButton("Start")
        self.stop_btn=QPushButton("Stop")
        self.ai_btn=QPushButton("Explain with AI")
        self.export_btn=QPushButton("Export Excel + PDF")

        self.start_btn.clicked.connect(lambda:self.timer.start(2000))
        self.stop_btn.clicked.connect(self.timer.stop)
        self.ai_btn.clicked.connect(self.open_ai)
        self.export_btn.clicked.connect(self.export_reports)

        for b in [self.start_btn,self.stop_btn,self.ai_btn,self.export_btn]:
            btns.addWidget(b)
        layout.addLayout(btns)

        self.setLayout(layout)
        self.set_role("Analyst")

    def set_role(self, role):
        if role=="Admin":
            pin,ok=QInputDialog.getText(self,"Admin Auth","Enter Admin PIN:",echo=QInputDialog.Password)
            if not ok or pin!=ADMIN_PIN:
                QMessageBox.warning(self,"Denied","Invalid PIN")
                self.role_box.setCurrentText("Analyst")
                return
        self.role=role
        admin=role=="Admin"
        self.start_btn.setEnabled(admin)
        self.stop_btn.setEnabled(admin)
        self.export_btn.setEnabled(admin)

    def monitor(self):
        r=traffic()
        df=pd.DataFrame([r])
        alert=0

        if self.rf.predict(df)[0]==1 or self.iso.predict(df)[0]==-1:
            s=risk(df.iloc[0])
            sev=severity(s)
            conf=confidence(s)
            ai=ai_escalation(s,sev)
            self.log_event(r,s,sev,conf,ai)
            alert=1

        if len(self.alert_rate)>=MAX_POINTS:
            self.alert_rate.pop(0)
        self.alert_rate.append(alert)

        self.auto_resolve()
        self.update_charts()

    def log_event(self,r,s,sev,conf,ai):
        row=self.table.rowCount()
        self.table.insertRow(row)
        self.severity_count[sev]+=1
        self.incident_age[row]={"LOW":2,"MEDIUM":3,"HIGH":4,"CRITICAL":999}[sev]
        self.role_snapshot[row]=self.role

        notes=f"AI Escalation Probability: {ai}%"

        vals=[
            datetime.now().strftime("%H:%M:%S"),
            threat_type(r),str(s),sev,str(conf),
            "ASSIGNED",self.role_snapshot[row],self.role_snapshot[row],
            notes,
            MITRE[threat_type(r)],ISO[threat_type(r)],str(ai)
        ]
        for i,v in enumerate(vals):
            self.table.setItem(row,i,QTableWidgetItem(v))

    def auto_resolve(self):
        for k in list(self.incident_age.keys()):
            self.incident_age[k]-=1
            if self.incident_age[k]<=0:
                self.table.setItem(k,5,QTableWidgetItem("RESOLVED"))
                del self.incident_age[k]

    def update_charts(self):
        self.fig_line.clear()
        ax=self.fig_line.add_subplot(111)
        ax.plot(self.alert_rate,marker="o")
        ax.set_ylim(0,1.2)
        ax.grid(True)
        self.line_canvas.draw()

        self.fig_pie.clear()
        ax2=self.fig_pie.add_subplot(111)
        vals=list(self.severity_count.values())
        labs=list(self.severity_count.keys())
        if sum(vals)==0: vals,labs=[1],["No Alerts"]
        ax2.pie(vals,labels=labs,autopct="%1.1f%%",radius=1.25)
        self.pie_canvas.draw()

    def open_ai(self):
        r=self.table.currentRow()
        if r>=0:
            AICopilotDialog(self.table.item(r,8).text(),self).exec_()

    def export_reports(self):
        wb=Workbook()
        ws=wb.active
        ws.append([self.table.horizontalHeaderItem(i).text()
                   for i in range(self.table.columnCount())])
        for r in range(self.table.rowCount()):
            ws.append([self.table.item(r,c).text()
                       for c in range(self.table.columnCount())])
        wb.save(EXCEL_FILE)
        QMessageBox.information(self,"Export","Reports Generated")

# ===================== SAFE RUN =====================
if __name__=="__main__":
    app=QApplication(sys.argv)
    win=SOCNIDS()
    win.show()
    sys.exit(app.exec_())

# ============================================================
# 🤖 APPEND-ONLY: AI COPILOT CONTEXT FIX (NO ORIGINAL CHANGES)
# ============================================================

_original_open_ai = SOCNIDS.open_ai

def _enhanced_open_ai(self):
    r = self.table.currentRow()
    if r < 0:
        QMessageBox.information(self, "AI Copilot", "Please select an incident row.")
        return

    context = (
        f"Time: {self.table.item(r,0).text()}\n"
        f"Threat: {self.table.item(r,1).text()}\n"
        f"Risk Score: {self.table.item(r,2).text()}\n"
        f"Severity: {self.table.item(r,3).text()}\n"
        f"Confidence: {self.table.item(r,4).text()}%\n"
        f"Status: {self.table.item(r,5).text()}\n"
        f"Role at Detection: {self.table.item(r,6).text()}\n"
        f"Owner: {self.table.item(r,7).text()}\n"
        f"MITRE Technique: {self.table.item(r,9).text()}\n"
        f"ISO Control: {self.table.item(r,10).text()}\n"
        f"AI Escalation Probability: {self.table.item(r,11).text()}%\n"
    )

    AICopilotDialog(context, self).exec_()

SOCNIDS.open_ai = _enhanced_open_ai

