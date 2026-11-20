import { afterEach, describe, expect, jest, test } from "@jest/globals";
import type { NextFunction, Request, Response } from "express";
import { Readable } from "stream";

type DetectedFileType = { mime: string } | undefined;
type ScanResult = { clean: boolean; threats: string[]; provider: string };
type UploadOptions = {
  filename: string;
  mimetype: string;
  subfolder: string;
};
type UploadResult = {
  key: string;
  mimetype: string;
  size: number;
  url: string;
};

async function importUploadController() {
  jest.resetModules();

  const fromFile = jest.fn<(path: string) => Promise<DetectedFileType>>();
  const unlinkSync = jest.fn<(path: string) => void>();
  const existsSync = jest.fn(() => true);
  const mkdirSync = jest.fn();
  const scanFile = jest.fn<(path: string) => Promise<ScanResult>>();
  const upload = jest.fn<
    (path: string, options: UploadOptions) => Promise<UploadResult>
  >();
  const logger = { security: jest.fn() };

  jest.doMock("file-type", () => ({
    __esModule: true,
    default: { fromFile },
  }));
  jest.doMock("fs", () => ({
    __esModule: true,
    default: { existsSync, mkdirSync, unlinkSync },
  }));
  jest.doMock("../src/config/env", () => ({
    env: {
      UPLOAD_DIR: "./uploads",
      ALLOWED_IMAGE_TYPES: ["image/jpeg", "image/png"],
      ALLOWED_DOC_TYPES: ["application/pdf"],
      MAX_FILE_SIZE: 1024,
    },
  }));
  jest.doMock("../src/utils/logger", () => ({ logger }));
  jest.doMock("../src/utils/storage.service", () => ({
    storageService: { upload },
  }));
  jest.doMock("../src/utils/malware.service", () => ({
    malwareService: { scanFile },
  }));

  const { UploadController } = await import("../src/utils/upload.controller");
  const { AppError } = await import("../src/middlewares/error.middleware");
  return {
    controller: new UploadController(),
    AppError,
    mocks: { fromFile, unlinkSync, scanFile, upload, logger },
  };
}

function fakeFile(path: string, originalname: string) {
  return {
    path,
    originalname,
    filename: `stored-${originalname}`,
    mimetype: "image/jpeg",
    size: 10,
    buffer: Buffer.alloc(0),
    fieldname: "file",
    encoding: "7bit",
    destination: "",
    stream: Readable.from([]),
  } as Express.Multer.File;
}

function fakeResponse() {
  return { json: jest.fn() } as unknown as Response;
}

function fakeNext() {
  return jest.fn() as NextFunction;
}

describe("UploadController", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test("uploadImage rejects a missing file", async () => {
    const { controller, AppError, mocks } = await importUploadController();
    const res = fakeResponse();
    const next = fakeNext();

    await controller.uploadImage({} as Request, res, next);

    expect(next).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.any(AppError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 400, message: "No file uploaded" }),
    );
    expect(mocks.upload).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });

  test("uploadImage removes a file when its type cannot be verified", async () => {
    const { controller, AppError, mocks } = await importUploadController();
    const file = fakeFile("/tmp/unknown", "unknown");
    mocks.fromFile.mockResolvedValueOnce(undefined);
    const next = fakeNext();

    await controller.uploadImage({ file } as Request, fakeResponse(), next);

    expect(mocks.unlinkSync).toHaveBeenCalledWith(file.path);
    expect(mocks.upload).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.any(AppError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 400, message: "Unable to verify file type" }),
    );
  });

  test("uploadImage removes a file with a disallowed detected type", async () => {
    const { controller, AppError, mocks } = await importUploadController();
    const file = fakeFile("/tmp/text", "text");
    mocks.fromFile.mockResolvedValueOnce({ mime: "text/plain" });
    const next = fakeNext();

    await controller.uploadImage({ file } as Request, fakeResponse(), next);

    expect(mocks.unlinkSync).toHaveBeenCalledWith(file.path);
    expect(mocks.upload).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.any(AppError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 400,
        message: "File type text/plain not allowed. Allowed: image/jpeg, image/png, application/pdf",
      }),
    );
  });

  test("uploadImage stores a valid file after a clean scan", async () => {
    const { controller, mocks } = await importUploadController();
    const file = fakeFile("/tmp/photo", "photo.jpg");
    const result = {
      key: "images/photo.jpg",
      mimetype: "image/jpeg",
      size: 10,
      url: "https://example.test/images/photo.jpg",
    };
    mocks.fromFile.mockResolvedValueOnce({ mime: "image/jpeg" });
    mocks.scanFile.mockResolvedValueOnce({
      clean: true,
      threats: [],
      provider: "test",
    });
    mocks.upload.mockResolvedValueOnce(result);
    const res = fakeResponse();

    await controller.uploadImage({ file } as Request, res, fakeNext());

    expect(mocks.upload).toHaveBeenCalledWith(file.path, {
      filename: file.filename,
      mimetype: "image/jpeg",
      subfolder: "images",
    });
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: {
        filename: "photo.jpg",
        originalname: file.originalname,
        mimetype: result.mimetype,
        size: result.size,
        url: result.url,
        key: result.key,
      },
    });
  });

  test("uploadImage removes an infected file without storing it", async () => {
    const { controller, AppError, mocks } = await importUploadController();
    const file = fakeFile("/tmp/infected", "infected.jpg");
    mocks.fromFile.mockResolvedValueOnce({ mime: "image/jpeg" });
    mocks.scanFile.mockResolvedValueOnce({
      clean: false,
      threats: ["test-threat"],
      provider: "test",
    });
    const next = fakeNext();

    await controller.uploadImage({ file } as Request, fakeResponse(), next);

    expect(mocks.unlinkSync).toHaveBeenCalledWith(file.path);
    expect(mocks.upload).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.any(AppError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 400,
        message: "File failed security scan: potential threat detected",
      }),
    );
  });

  test("uploadMultiple rejects an empty file list", async () => {
    const { controller, AppError, mocks } = await importUploadController();
    const next = fakeNext();

    await controller.uploadMultiple(
      { files: [] as Express.Multer.File[] } as Request,
      fakeResponse(),
      next,
    );

    expect(next).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.any(AppError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 400, message: "No files uploaded" }),
    );
    expect(mocks.upload).not.toHaveBeenCalled();
  });

  test("uploadMultiple returns successful results for valid files", async () => {
    const { controller, mocks } = await importUploadController();
    const files = [fakeFile("/tmp/one", "one.jpg"), fakeFile("/tmp/two", "two.jpg")];
    mocks.fromFile.mockResolvedValue({ mime: "image/png" });
    mocks.scanFile.mockResolvedValue({
      clean: true,
      threats: [],
      provider: "test",
    });
    const result = {
      key: "images/stored.jpg",
      mimetype: "image/png",
      size: 10,
      url: "https://example.test/images/stored.jpg",
    };
    mocks.upload.mockResolvedValue(result);
    const res = fakeResponse();

    await controller.uploadMultiple({ files } as Request, res, fakeNext());

    expect(mocks.upload).toHaveBeenCalledTimes(2);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: files.map((file) => ({
        filename: "stored.jpg",
        originalname: file.originalname,
        mimetype: result.mimetype,
        size: result.size,
        url: result.url,
        key: result.key,
      })),
    });
  });

  test("uploadMultiple removes every file when one has a disallowed type", async () => {
    const { controller, AppError, mocks } = await importUploadController();
    const files = [fakeFile("/tmp/disallowed", "text.txt"), fakeFile("/tmp/other", "other.jpg")];
    mocks.fromFile.mockResolvedValueOnce({ mime: "text/plain" });
    const next = fakeNext();

    await controller.uploadMultiple({ files } as Request, fakeResponse(), next);

    expect(mocks.unlinkSync).toHaveBeenCalledTimes(files.length);
    expect(mocks.unlinkSync).toHaveBeenNthCalledWith(1, files[0].path);
    expect(mocks.unlinkSync).toHaveBeenNthCalledWith(2, files[1].path);
    expect(mocks.upload).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.any(AppError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 400,
        message: "File type text/plain not allowed for text.txt",
      }),
    );
  });
});
