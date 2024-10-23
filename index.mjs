import express from "express";
import multer from "multer";
import moment from "moment";
import cors from "cors";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";

//json檔案讀取的設定
const defaultDatas = { user: [], products: [] };
const db = new Low(new JSONFile("./db.json"), defaultDatas);
await db.read();
// console.log(process.env.XXX_API_KEY); // 取得環境參數

const upload = multer();

// 跨網域處理
let whiteList = [
	"http://localhost:5500",
	"http://127.0.0.01:5500",
	"http://localhost:3000",
	"http://127.0.0.01:3000",
]; // 宣告白名單
let corsOption = {
	credentials: true, //cookie帶上來
	origin(origin, callback) {
		if (!origin || whiteList.includes(origin)) {
			callback(null, true);
		} else {
			callback(new Error("不允許連線"));
		}
	},
};

const app = express();
const port = 3005;
app.use(cors(corsOption));

app.get("/", (req, res) => {
	res.send("首頁");
});

app.listen(port, () => {
	console.log(`server is running at http://localhost:${port}`);
});

function checkToken(req, res, next) {
	let token = req.get("Authorization");
	// console.log(token);

	if (token && token.indexOf("Bearer ") == 0) {
		token = token.slice(7);
		jwt.verify(token, process.env.SECRET_KEY, (error, decoded) => {
			if (error) {
				return res.status(401).json({
					ressult: "fail",
					message: "驗證失敗，請重新登入",
				});
			}

			req.decoded = decoded; //讓下一段路由可以取得decoded
			next();
		});
	} else {
		return res.status(401).json({
			ressult: "fail",
			message: "沒有驗證資料，請重新登入",
		});
	}
}
