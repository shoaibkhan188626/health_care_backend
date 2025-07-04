import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const connectDB = async () => {
  try {
    const uri =
      process.env.NODE_ENV === "production"
        ? process.env.MONGO_CLOUD_URI
        : process.env.MONGO_LOCAL_URI;

    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000, // Timeout for connection
      socketTimeoutMS: 45000, // Prevent socket timeouts
    });

    console.log(`MongoDB connected: ${mongoose.connection.host}`);

    // Handle connection errors
    mongoose.connection.on("error", (err) => {
      console.error("MongoDB connection error:", err);
    });

    // Handle disconnection
    mongoose.connection.on("disconnected", () => {
      console.log("MongoDB disconnected. Attempting to reconnect...");
      setTimeout(connectDB, 5000); // Retry after 5s
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1); // Exit on failure
  }
};

// Export connection function and mongoose instance
export { connectDB, mongoose };
