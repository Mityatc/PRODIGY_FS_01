import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.json({ success: false, message: 'Not authorized. Please log in again.' });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (tokenDecode.id) {
            req.body.userId = tokenDecode.id; // Store the decoded user ID in the request body
        } else {
            return res.json({ success: false, message: 'Not authorized. Please log in again.' });
        }

        next();  // Proceed to the next middleware or route handler
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export default userAuth;
