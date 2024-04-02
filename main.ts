// deno-lint-ignore-file no-empty-interface

import {crypto} from "https://deno.land/std@0.221.0/crypto/mod.ts";
import {decodeBase64} from "https://deno.land/std@0.221.0/encoding/base64.ts";
import {create as createJwtToken, verify as verifyJwtToken, Payload} from "https://deno.land/x/djwt@v3.0.2/mod.ts";

const authKey = await loadAuthKey();
const db = await Deno.openKv();
const dbTtl = 60 * 60 * 24 * 7;

Deno.serve(handler);

async function handler(request: Request): Promise<Response> {
  if (request.method !== "POST") {
    return createErrorResponse(ApiError.InvalidRequestMethod);
  }
  try {
    const {method, data} = await request.json() as JSONRequest;
    switch (method) {
      case Method.Init:
        return handleInit(data as InitRequestData, request);
      case Method.Send:
        return handleSend(data as SendRequestData, request);
      case Method.Receive:
        return handleReceive(data as ReceiveRequestData, request);
      case Method.Get:
        return handleGet(data as GetRequestData, request);
      case Method.Confirm:
        return handleConfirm(data as ConfirmRequestData, request);
      default:
        return createErrorResponse(
          ApiError.create(`Method ${method} not found.`, HttpStatus.NotFound),
        );
    }
  } catch (err) {
    if (err instanceof ApiError) {
      return createResponse(err.statusCode, err);
    }
    return createErrorResponse(ApiError.wrap("Internal Server Error", err));
  }
}

async function handleInit({publicKey, name}: InitRequestData, _: Request): Promise<Response> {
  if (!publicKey) {
    return createErrorResponse(ApiError.InvalidPublicKey);
  }
  try {
    // generate account data
    const account: Account = {
      id: crypto.randomUUID(),
      createdAt: new Date().toUTCString(),
      publicKey,
      name,
    };

    // generate auth token
    const token = await generateToken(account);

    // store to database
    await db.set([DbPrefix.Account, account.id], account);

    // generate response data
    const data: InitResponseData = {
      account,
      token,
    };

    return createResponse(200, {data});
  } catch (err) {
    return createErrorResponse(ApiError.wrap("Failed to init", err));
  }
}

async function handleSend({to, content}: SendRequestData, req: Request): Promise<Response> {
  const senderId = await checkAuth(req);

  try {
    // generate message
    const msg: Message = {
      id: crypto.randomUUID(),
      from: senderId,
      createdAt: new Date().toUTCString(),
      to,
      content,
    };

    // save message to database
    await db.set([DbPrefix.Message, to, msg.id], msg, {
      expireIn: Date.now() + dbTtl,
    });

    // generate response
    const data: SendResponseData = {
      id: msg.id,
      createdAt: msg.createdAt,
    };

    return createResponse(200, {data});
  } catch (err) {
    return createResponse(500, {error: `failed to send: ${err}`});
  }
}

async function handleReceive(_: ReceiveRequestData, req: Request): Promise<Response> {
  const receiverId = await checkAuth(req);
  const messages: Message[] = [];

  // fetch new messages from database
  const dbMessages = db.list<Message>({
    prefix: [DbPrefix.Message, receiverId],
  });
  for await (const {value: msg} of dbMessages) {
    messages.push(msg);
  }

  // generate response
  const data: ReceiveResponseData = {messages};

  return createResponse(200, {data});
}

async function handleGet({id}: GetRequestData, _?: Request): Promise<Response> {
  // load account from database
  const account = await db.get<Account>([DbPrefix.Account, id]);

  // check if account exists
  if (!account.value) {
    return createErrorResponse(ApiError.create(`Account ${id} not found.`, HttpStatus.NotFound));
  }

  // generate response data
  const data: GetResponseData = {account: account.value};

  return createResponse(200, {data});
}

async function handleConfirm({messages}: ConfirmRequestData, req: Request): Promise<Response> {
  const confirmerId = await checkAuth(req);

  await Promise.all(messages.map(({id}) => db.delete([DbPrefix.Message, confirmerId, id])));

  const data = {};

  return createResponse(200, {data});
}

async function checkAuth(req: Request): Promise<string> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader) {
    throw ApiError.InvalidAuthHeader;
  }
  try {
    return await verifyToken(authHeader);
  } catch (err) {
    throw ApiError.wrap("Unauthorized", err, HttpStatus.Unauthorized);
  }
}

async function generateToken(account: Account): Promise<string> {
  const payload: Token = {
    id: account.id,
    rn: crypto.randomUUID(),
  };
  return await createJwtToken({alg: "HS512", typ: "JWT"}, payload, authKey);
}

async function verifyToken(token: string): Promise<string> {
  const {id} = await verifyJwtToken<Token>(token, authKey);
  return id;
}

function createResponse(statusCode: number, body: JSONResponse | ApiError): Response {
  const json = JSON.stringify(body);
  return new Response(json, {
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
    },
    status: statusCode,
  });
}

function createErrorResponse(err: ApiError): Response {
  return createResponse(err.statusCode, err);
}

async function loadAuthKey(): Promise<CryptoKey> {
  const keyFromEnv = Deno.env.get("AUTH_KEY");
  return await crypto.subtle.importKey(
    "raw",
    decodeBase64(keyFromEnv || await Deno.readTextFile(".defaultAuthKey")),
    {name: "HMAC", hash: "SHA-512"},
    true,
    ["sign", "verify"],
  );
}

enum Method {
  Init = "init",
  Send = "send",
  Receive = "receive",
  Get = "get",
  Confirm = "confirm",
}

enum HttpStatus {
  OK = 200,
  BadRequest = 400,
  Unauthorized = 401,
  NotFound = 404,
  MethodNotAllowed = 405,
  InternalServerError = 500,
}

class ApiError extends Error {
  readonly statusCode: HttpStatus;

  public constructor(msg: string, statusCode: HttpStatus = HttpStatus.InternalServerError) {
    super(msg);
    this.statusCode = statusCode;
  }

  toJSON(): { error: string, code: HttpStatus } {
    return {
      error: this.message,
      code: this.statusCode,
    };
  }

  public static create(msg: string, statusCode: HttpStatus = HttpStatus.InternalServerError): ApiError {
    return new this(msg, statusCode);
  }

  public static wrap(msg: string, err: ApiError, statusCode?: HttpStatus): ApiError {
    return this.create(`${msg}: ${err.message}`, statusCode || err.statusCode);
  }

  public static readonly InvalidRequestMethod = this.create(`Invalid request method, only POST is allowed.`, HttpStatus.MethodNotAllowed);
  public static readonly InvalidPublicKey = this.create(`Invalid public key.`, HttpStatus.BadRequest);
  public static readonly InvalidAuthHeader = this.create(`Invalid authorization header.`, HttpStatus.Unauthorized);
}

enum DbPrefix {
  Account = "acc",
  Message = "msg",
}

interface JSONRequest<T = unknown> {
  method: string,
  data: T,
}

interface JSONResponse<T = unknown> {
  error?: string;
  data?: T,
}

interface Account {
  id: string;
  name?: string;
  publicKey: string;
  createdAt: string;
}

interface Token extends Payload {
  id: string; // account id
  rn: string; // random string
}

interface Message {
  id: string;
  from: string;
  to: string;
  content: string;
  createdAt: string;
}

interface InitRequestData {
  publicKey: string;
  name?: string;
}

interface InitResponseData {
  account: Account;
  token: string;
}

interface SendRequestData {
  to: string;
  content: string;
}

interface SendResponseData {
  id: string;
  createdAt: string;
}

interface ReceiveRequestData {
}


interface ReceiveResponseData {
  messages: Message[];
}

interface GetRequestData {
  id: string;
}

interface GetResponseData {
  account: Account;
}

interface ConfirmRequestData {
  messages: { id: string }[];
}

interface ConfirmResponseData {
}