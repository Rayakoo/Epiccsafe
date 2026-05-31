import os
import httpx
import logging
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


def send_report_confirmation(to_email: str, ticket_id: str, url: str, status: str):
    subject = f"[EpiccSafe] Laporan #{ticket_id} telah diterima"
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #800000; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 20px;">EpiccSafe</h1>
        </div>
        <div style="padding: 24px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px;">
        <h2 style="color: #800000; margin-top: 0;">Laporan Diterima</h2>
        <p>Halo,</p>
        <p>Laporan Anda telah kami terima dan sedang diproses.</p>
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
                <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold; color: #e37400;">{status}</td>
            </tr>
        </table>
        <p style="color: #666; font-size: 14px;">Anda dapat memeriksa status laporan menggunakan Ticket ID di atas.</p>
        <p style="color: #666; font-size: 12px; margin-top: 24px;">&mdash; Tim EpiccSafe</p>
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
