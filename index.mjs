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

app.post("/api/users/login", upload.none(), (req, res) => {
	const { account, password } = req.body;
	let message = `${account} 登入成功`;
   
	const user = db.data.user.find(
	 (u) => u.account == account && u.password == password
	);
   
	if (!user) {
	 message = "登入失敗";
	 return res.status(404).json({ result: "fail", message });
	}
   
	//將帳號密碼押入token,並傳入密鑰
	let token = jwt.sign(
	 {
	  account: user.account,
	  name: user.name,
	  mail: user.mail,
	  head: user.head,
	 },
	 process.env.SECRET_KEY,
	 {
	  expiresIn: "30m",
	 }
	);
   
	res.status(200).json({ result: "success", message, data: token });
   });
   
   app.get("/api/users/logout", checkToken, (req, res) => {
	console.log(req.decoded); //從checkToken取得的
	let message = `登出成功`;
   
	//核發一個失效的token(一拿到即過期)
	let token = jwt.sign(
	 {
	  account: req.decoded.account,
	  name: req.decoded.name,
	  mail: req.decoded.mail,
	  head: req.decoded.head,
	 },
	 process.env.SECRET_KEY,
	 {
	  expiresIn: "-10s",
	 }
	);
   
	res.status(200).json({ result: "success", message, data: token });
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
