const bcrypt = require('bcrypt');
const User = require('../models/userModel');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const register = async (req,res) => {
    try {
        
        if (req.body.username === undefined || req.body.email === undefined || req.body.password === undefined ) {
            return res.status(400).json({error: "Authentification failed: Missing email, username, password."});
        }

        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
          return res.status(422).json({ error: "Email already exists" });
        }
        

        const hash = await bcrypt.hash(req.body.password, saltRounds);

        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: hash
        })

        await user.save();
        // const token = jwt.sign({ data:user._id }, process.env.SECRET_KEY, { expiresIn: '24h' })
        res.status(201).json({ ...user._doc, message: "Succesfully Created Account "})

    } catch (error) {
        console.error("Signup error: ", error);
        res.status(500).send("Internal server error");
        
    }
}

const signin = async (req,res) => {
    
    try {
        const username = req.body.username;
        const email = req.body.email;
        const password = req.body.password;

        if (username === undefined || email === undefined || password === undefined ) {
            return res.status(400).json({error: "Authentification failed: Missing email, username, password."});
        }

        const user = await User.findOne({email}).select("email password username").exec();

        if(!user) {
            return res.status(422).json({error: " user not found."});
        }

        console.log(user)

        const passwordMatch = await bcrypt.compare(password, user.password);
        console.log("Password match:", passwordMatch);

       

        if(passwordMatch) {
            const token = jwt.sign({ data: user._id }, process.env.SECRET_KEY, { expiresIn: '24h' })
           
            // user.password = undefined;
            return res.status(200).json({token,...user._doc, message: "Login Successful"})
        }else {
            return res.status(401).json({error: "Incorrect Password"});
        }

    } catch (err) {
        console.error("Signin error:", err);
        res.status(500).send("Internal server error");
    }
}

const updatePassword = async (req, res) => {
    try {
        
      const decoded = req.decoded;
      const userId = decoded.data

      const email = req.body.email;
      const password = req.body.newPassword;

      if (email === "" || password === "" ) {
        return res.status(400).json({error: "Authentification failed: Missing email, username, password."});
      }
      
      const user = await User.findOne({email: email});
      if (!user) {
        return res.status(401).json({ error: "User is not found" });
      }
  
      // Hash the new password
      const hash = bcrypt.hashSync(password, saltRounds);
  
      // Find the user and update password
      const updatedUser = await User.findByIdAndUpdate(userId, { password: hash }, { new: true });
  
      if (!updatedUser) {
        return res.status(400).json({ error: "user is not found" });
      } else {
        return res.status(200).json({ message: "Updated Password Successfully" });
      }
    } catch (error) {
      console.error("Update password error:", error);
      res.status(500).send("Internal server error");
    }
};

const getUserById = async (req,res) => {
    try {
        const decoded = req.decoded;
        const userId = decoded.data;

        if (!userId) return res.status(400).json({error: "User is not exist!"})

        const user = await User.findById(userId)
        res.status(200).json(user)
    } catch (error) {
        console.error("Data Fetching error:", error);
        res.status(500).send("Internal server error");
        
    }
}



  

module.exports={
    register,
    signin,
    updatePassword,
    getUserById,
   
}
