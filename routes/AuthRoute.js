const {Signup, Login, getUserProfile} = require("../controller/AuthController");
const { userVerification } = require("../middleware/AuthMiddleware");
const router = require("express").Router();

router.post("/signup", Signup);
router.post("/login", Login);
router.post("/user/profile", userVerification, getUserProfile);

module.exports = router;