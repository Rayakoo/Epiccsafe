import os
import re
import smtplib
import uuid
import logging
from datetime import datetime
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

logger = logging.getLogger(__name__)


def _build_message(to: str, subject: str, html: str, plain: str = "") -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["From"] = f"EpiccSafe <{SMTP_EMAIL}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{uuid.uuid4()}@epiccsafe>"
    msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0700")
    msg.attach(MIMEText(plain or _strip_html(html), "plain"))
    msg.attach(MIMEText(html, "html"))
    return msg


def _strip_html(html: str) -> str:
    import re
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _send_email(to: str, subject: str, html: str) -> bool:
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        logger.warning("SMTP_EMAIL atau SMTP_PASSWORD tidak dikonfigurasi, email tidak dikirim")
        return False

    try:
        msg = _build_message(to, subject, html)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, [to], msg.as_string())

        logger.info(f"Email berhasil dikirim ke {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Gagal kirim email ke {to}: {e}")
        return False


def send_report_confirmation(to_email: str, ticket_id: str, url: str, status: str, reporter_name: str = "", description: str = ""):
    subject = f"[EpiccSafe] Laporan #{ticket_id} telah diterima"
    today = datetime.now().strftime("%d/%m/%Y")
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #800000; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 20px;">EpiccSafe</h1>
        </div>
        <div style="padding: 24px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px; line-height: 1.6;">
            <p>Halo {reporter_name or 'Pengguna'},</p>
            <p>Terima kasih telah menggunakan layanan pelaporan phishing di EpiccSafe.</p>
            <p>Laporan Anda telah berhasil kami terima dan sedang diproses oleh tim keamanan kami.</p>
            <pre style="font-family: monospace; background: #f5f5f5; padding: 16px; border-radius: 4px; font-size: 13px;">
━━━━━━━━━━━━━━━━━━
DETAIL PELAPORAN
━━━━━━━━━━━━━━━━━━
E-Ticket       : #{ticket_id}
Tanggal Laporan : {today}
Status Pelaporan : Menunggu Verifikasi
Kategori       : Phishing / Scam / Suspicious Link
Email Pelapor  : {to_email}
━━━━━━━━━━━━━━━━━━
RINGKASAN LAPORAN
━━━━━━━━━━━━━━━━━━
URL / Domain Dilaporkan:
{url}

Catatan Tambahan:
{description or '-'}
━━━━━━━━━━━━━━━━━━
LANGKAH SELANJUTNYA
━━━━━━━━━━━━━━━━━━</pre>
            <p>• Tim kami akan melakukan verifikasi terhadap laporan Anda.</p>
            <p>• Anda dapat memantau perkembangan laporan menggunakan nomor e-ticket di atas.</p>
            <p>• Jika diperlukan informasi tambahan, kami akan menghubungi Anda melalui email ini.</p>
            <p>Mohon untuk tidak membuka kembali tautan mencurigakan tersebut dan segera mengganti password akun terkait apabila Anda sempat memasukkan data pribadi.</p>
            <p>Terima kasih telah membantu menjaga keamanan digital bersama.</p>
            <p>Hormat kami,<br>Tim Keamanan EpiccSafe</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 13px; color: #666;">Ingin belajar lebih lanjut tentang keamanan digital? Ikuti tes edukasi phishing kami:<br>
            <a href="https://forms.gle/CrmQHgtQuyMqW4Lv7" style="color: #800000;">https://forms.gle/CrmQHgtQuyMqW4Lv7</a></p>
        </div>
    </div>
    """
    _send_email(to_email, subject, html)


def _send_email_single_connection(recipients: list[tuple[str, str, str]], is_bulk: bool = False) -> tuple[int, int]:
    sent = 0
    failed = 0
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        logger.warning("SMTP tidak dikonfigurasi")
        return sent, failed
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            for to, subject, html in recipients:
                try:
                    msg = _build_message(to, subject, html)
                    if is_bulk:
                        msg["Precedence"] = "bulk"
                        msg["List-Unsubscribe"] = f"<mailto:{SMTP_EMAIL}?subject=unsubscribe>"
                    server.sendmail(SMTP_EMAIL, [to], msg.as_string())
                    sent += 1
                except Exception as e:
                    logger.error(f"Gagal kirim ke {to}: {e}")
                    failed += 1
    except Exception as e:
        logger.error(f"Gagal koneksi SMTP: {e}")
        failed = len(recipients)
    return sent, failed


def send_broadcast_warning(to_email: str, url: str, reporter_name: str = ""):
    subject = f"[EpiccSafe] Peringatan: URL Phishing Terdeteksi"
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #800000; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 20px;">EpiccSafe</h1>
        </div>
        <div style="padding: 24px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px; line-height: 1.6;">
            <p>Halo {reporter_name or 'Pengguna'},</p>
            <p>Kami dari Tim Keamanan EpiccSafe menemukan bahwa URL berikut telah diklasifikasikan sebagai <strong>phishing</strong>:</p>
            <p style="background: #fff3f3; border: 1px solid #ffcccc; padding: 12px; border-radius: 4px; word-break: break-all; font-family: monospace;">
                {url}
            </p>
            <p>URL tersebut mengandung elemen berbahaya yang dirancang untuk mencuri informasi pribadi seperti username, password, atau data sensitif lainnya. Tim kami saat ini sedang menangani dan memblokir URL tersebut agar tidak dapat diakses lebih lanjut.</p>
            <p><strong>Kami mengimbau Anda untuk:</strong></p>
            <p>• Tidak mengakses atau membuka URL tersebut dalam keadaan apa pun.</p>
            <p>• Tidak memasukkan data pribadi apa pun jika Anda sudah terlanjur membukanya.</p>
            <p>• Segera mengganti password akun Anda jika merasa data Anda telah dikompromikan.</p>
            <p>• Melaporkan setiap tautan mencurigakan lainnya melalui platform EpiccSafe.</p>
            <p>Keselamatan dan keamanan Anda adalah prioritas utama kami. Jika Anda memiliki pertanyaan atau membutuhkan bantuan lebih lanjut, jangan ragu untuk menghubungi tim kami.</p>
            <p>Terima kasih atas perhatian dan kerja samanya.</p>
            <p>Hormat kami,<br>Tim Keamanan EpiccSafe</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 13px; color: #666;">Ingin belajar lebih lanjut tentang keamanan digital? Ikuti tes edukasi phishing kami:<br>
            <a href="https://forms.gle/CrmQHgtQuyMqW4Lv7" style="color: #800000;">https://forms.gle/CrmQHgtQuyMqW4Lv7</a></p>
        </div>
    </div>
    """
    _send_email(to_email, subject, html)


def broadcast_bulk(recipients: list[tuple[str, str]], url: str) -> tuple[int, int]:
    subject = "[EpiccSafe] Peringatan Keamanan: URL Berbahaya Terdeteksi"
    prepared = []
    for email, name in recipients:
        html = _broadcast_html(url, name)
        prepared.append((email, subject, html))
    return _send_email_single_connection(prepared, is_bulk=True)


def _broadcast_html(url: str, reporter_name: str) -> str:
    return f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #800000; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 20px;">EpiccSafe</h1>
        </div>
        <div style="padding: 24px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px; line-height: 1.6;">
            <p>Halo {reporter_name or 'Pengguna'},</p>
            <p>Kami dari Tim Keamanan EpiccSafe menemukan bahwa URL berikut telah diklasifikasikan sebagai <strong>phishing</strong>:</p>
            <p style="background: #fff3f3; border: 1px solid #ffcccc; padding: 12px; border-radius: 4px; word-break: break-all; font-family: monospace;">
                {url}
            </p>
            <p>URL tersebut mengandung elemen berbahaya yang dirancang untuk mencuri informasi pribadi seperti username, password, atau data sensitif lainnya. Tim kami saat ini sedang menangani dan memblokir URL tersebut agar tidak dapat diakses lebih lanjut.</p>
            <p><strong>Kami mengimbau Anda untuk:</strong></p>
            <p>• Tidak mengakses atau membuka URL tersebut dalam keadaan apa pun.</p>
            <p>• Tidak memasukkan data pribadi apa pun jika Anda sudah terlanjut membukanya.</p>
            <p>• Segera mengganti password akun Anda jika merasa data Anda telah dikompromikan.</p>
            <p>• Melaporkan setiap tautan mencurigakan lainnya melalui platform EpiccSafe.</p>
            <p>Keselamatan dan keamanan Anda adalah prioritas utama kami. Jika Anda memiliki pertanyaan atau membutuhkan bantuan lebih lanjut, jangan ragu untuk menghubungi tim kami.</p>
            <p>Terima kasih atas perhatian dan kerja samanya.</p>
            <p>Hormat kami,<br>Tim Keamanan EpiccSafe</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 13px; color: #666;">Ingin belajar lebih lanjut tentang keamanan digital? Ikuti tes edukasi phishing kami:<br>
            <a href="https://forms.gle/CrmQHgtQuyMqW4Lv7" style="color: #800000;">https://forms.gle/CrmQHgtQuyMqW4Lv7</a></p>
        </div>
    </div>
    """


def send_status_update(to_email: str, ticket_id: str, url: str, new_status: str, final_status: Optional[str] = None):
    status_label = final_status or new_status
    subject = f"[EpiccSafe] Status laporan #{ticket_id} telah diperbarui"
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #800000; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 20px;">EpiccSafe</h1>
        </div>
        <div style="padding: 24px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px;">
        <h2 style="color: #800000; margin-top: 0;">Status Laporan Diperbarui</h2>
        <p>Halo,</p>
        <p>Status laporan Anda telah diperbarui.</p>
        <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;">Ticket ID</td>
                <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">{ticket_id}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;">URL</td>
                <td style="padding: 8px; border-bottom: 1px solid #ddd;">{url}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;">Status</td>
                <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold; color: #059669;">{status_label}</td>
            </tr>
        </table>
        <p style="color: #666; font-size: 12px; margin-top: 24px;">&mdash; Tim EpiccSafe</p>
        </div>
    </div>
    """
    _send_email(to_email, subject, html)
