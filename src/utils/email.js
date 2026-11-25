import nodemailer from "nodemailer";

const sendEmail = async ({ to, subject, text }) => {
    const { SMTP_HOST, SMTP_POST, SMTP_USER, SMTP_PASS, EMAIL_FROM } = process.env

    //LOCAL DEVELOPMENT ONLY LOG THE LINK FOR TESTING
    if (!SMTP_HOST || !SMTP_POST || !SMTP_PASS) {
        if (process.env === "production") {
            throw new Error("Email service is not configured")
        }

        console.log(`\n[DEVELOPMENT EMAIL] TO: ${to}`)
        console.log(`Subject: ${subject}`)
        console.log(text)
        console.log("[END DEVELOPMENT EMAIL]\n")
        return;
    }

    const transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: Number(SMPT_PORT || 587),
        secure: Number(SMPT_PORT) === 465,
        auth: {
            user: SMPT_USER,
            pass: SMTP_PASS
        }
    })

    await transporter.sendMail({
        from: EMAIL_FROM || SMPT_USER,
        to,
        subject,
        text
    })
};

export default sendEmail