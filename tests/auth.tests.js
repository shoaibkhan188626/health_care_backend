import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";
import User from "../models/user.js";
import { register, login } from "../controllers/auth.controller.js";
import { ValidationError, UnauthorizedError } from "../utils/error.js";

describe("Auth Controller", () => {
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    await mongoose.connect(mongoServer.getUri());
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  afterEach(async () => {
    await User.deleteMany({});
  });

  it("should register a new user", async () => {
    const req = {
      body: {
        name: "Dr. Priya Sharma",
        email: "priya@example.com",
        phone: "9876543210",
        password: "Secure@123",
        role: "doctor",
        hospitalId: "507f191e810c19729de860ea",
        address: { city: "Mumbai", pincode: "400001" },
      },
      ip: "127.0.0.1",
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const next = jest.fn();

    // Mock httpClient
    jest.spyOn(require("../utils/httpclient.js"), "get").mockResolvedValue({
      data: {
        hospital: { id: "507f191e810c19729de860ea", name: "Mock Hospital" },
      },
    });

    await register(req, res, next);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "User registered successfully",
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      }),
    );
  });

  it("should fail login with invalid credentials", async () => {
    const req = {
      body: { email: "priya@example.com", password: "Wrong@123" },
      ip: "127.0.0.1",
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const next = jest.fn();

    await login(req, res, next);

    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
  });
});
