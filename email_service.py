import os
import httpx
import logging
from datetime import datetime
from typing import Optional

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "EpiccSafe <noreply@epiccsafe.com>")

RESEND_API_URL = "https://api.resend.com/emails"

logger = logging.getLogger(__name__)


def _send_email(to: str, subject: str, html: str) -> bool:
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY tidak dikonfigurasi, email tidak dikirim")
        return False

    try:
        resp = httpx.post(
            RESEND_API_URL,
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": EMAIL_FROM,
                "to": [to],
                "subject": subject,
                "html": html,
            },
            timeout=15,
        )
        if resp.is_success:
            logger.info(f"Email berhasil dikirim ke {to}: {subject}")
            return True
        else:
            logger.error(f"Gagal kirim email ke {to}: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Exception saat kirim email ke {to}: {e}")
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
