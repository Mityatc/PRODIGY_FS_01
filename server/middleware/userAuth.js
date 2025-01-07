import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.json({ success: false, message: 'Not authorized. Please log in again.' });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        req.body.userId = tokenDecode.id;
        next();
    } catch (error) {
        console.error("JWT Verification Error on Vercel:", error);
        return res.json({ success: false, message: 'Not authorized. Please log in again.' });
    }
};

export default userAuth;
