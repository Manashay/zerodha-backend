const User = require("../model/UserModel");
const {createSecretToken} = require("../util/SecretToken");
const bcrypt = require("bcrypt");

module.exports.Signup = async (req, res, next) => {
    try{
        const {email, password, username, createdAt} = req.body;
        const existingUser = await User.findOne({email});
        if(existingUser){
            return res.json({message: "User already exists"});
        }
        const user = await User.create({email, password, username, createdAt});
        const token = createSecretToken(user._id);
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,    // More secure (prevents XSS)
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day
            sameSite: "none",   // Allows cookie to be sent across local ports
            secure: true,     // Set to true only if using HTTPS
        });
        res
         .status(201)
         .json({message: "User signed in successfully", success: true, user});
        next();
    } catch (error){
        console.log(error);
    }
};

module.exports.Login = async (req, res, next) => {
    try{
        const {email, password} = req.body;
        if(!email || !password){
            return res.json({message: "All fields are required"});
        }
        const user = await User.findOne({email});
        if(!user){
            return res.json({message: "Incorrect password or email"});
        }
        const auth = await bcrypt.compare(password, user.password);
        if(!auth){
            return res.json({message: "incorrect password or email"});
        }
        const token = createSecretToken(user._id);
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,    // More secure (prevents XSS)
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day
            sameSite: "none",   // Allows cookie to be sent across local ports
            secure: true,     // Set to true only if using HTTPS
        });
        res.status(201).json({message: "User logged in successfully", success: true});
        next();
    } catch (error){
        console.log(error);
    }
};

// ... existing Signup and Login code ...

module.exports.getUserProfile = async (req, res) => {
  try {
    // req.user is populated by your userVerification middleware
    const user = await User.findById(req.user._id); 
    
    if (!user) {
      return res.json({ status: false, message: "User not found" });
    }

    res.status(200).json({
      status: true,
      username: user.username,
      email: user.email,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: false, message: "Server error" });
  }
};