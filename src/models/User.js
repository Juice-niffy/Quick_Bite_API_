import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      require: [true, "Name is required"],
      trim: true,
    },

    email: {
      type: String,
      require: [true, "Email is required"],
      unique: true,
      index: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      require: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 charaters"],
      select: false,
      validate: {
        validator: function (v) {
          const uppercase = /^[A-Z]/.test(v);
          const hasSymbol = /[!@#$%^&*_\-+=\\|/,.]/.test(v);
          const hasNumber = /[0-9]/.test(v);

          return uppercase && hasSymbol && hasNumber;
        },
        message:
          "Password must contain UPPERCASE as first letter and at least one symbol (!@#$%^&*_ etc) and number",
      },
    },

    role: {
      type: String,
      enum: ["Customer", "RestaurantOwner", "Rider", "Admin"],
      default: "Customer",
      require: true,
    },

    phone: {
      type: String,
      trim: true,
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    // Email verification
    emailVerified: {
      type: Boolean,
      default: false,
    },

    emailVerificationToken: {
      type: String,
      default: null,
    },

    emailVerificationExpires: {
      type: Date,
      default: null,
    },
    // Password reset
    passwordResetToken: {
      type: String,
      default: null,
      select: false,
    },

    passwordResetExpires: {
      type: Date,
      default: null,
      select: false,
    },
  },
  { timestamps: true },
);

//HASH PASSWORD BEFORE SAVING
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

//COMPARE PASSWORD BEFORE LOGIN
userSchema.methods.comparePassword = async function comparePassword(
  userPassword,
) {
  return bcrypt.compare(userPassword, this.password);
};

//GENERATE EMAIL VERIFICATION TOKEN
userSchema.methods.createEmailVerificationToken = function () {
  const token = crypto.randomBytes(32).toString("hex");
  this.emailVerificationToken = crypto
    .createHash("sha256")
    .upadate(token)
    .digest("hex");
  this.email.emailVerificationExpires = Date.now() + 10 * 60 * 1000; //LAST FOR 10MIN
  return token; //RETURN UNHASHED TO SEND TO USER/EMAIL
};

//GENERATE PASSWORD RESET TOKEN
userSchema.methods.createPasswordResetToken = function () {
  const token = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
    .createHash("sha256")
    .upadate(token)
    .digest("hex");
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; //LAST FOR 10MIN
  return token;
};

//SENSITIVE FIELD NOT EXPOSE
const hideSensitive = (doc, ret) => {
  delete ret.password;
  delete ret.emailVerificationToken;
  delete ret.emailVerificationExpires;
  delete ret.passwordResetExpires;
  delete ret.passwordResetToken;
  delete ret._v;
  return ret;
};
userSchema.set("toJSON", { transform: hideSensitive });
userSchema.set("toOBJECT", { transform: hideSensitive });

const User = mongoose.model("User", userSchema);

export default User;
