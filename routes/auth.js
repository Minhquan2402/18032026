let express = require('express');
let router = express.Router()
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let authHandler = require('../utils/authHandler')
let { body, validationResult } = require('express-validator')

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return;
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            // Tạo JWT token với RS256
            const token = authHandler.generateToken({
                userId: user._id,
                username: user.username,
                email: user.email
            });
            res.send({
                id: user._id,
                token: token,
                message: 'Đăng nhập thành công'
            })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

// Endpoint /me - Lấy thông tin user hiện tại
router.get('/me', authHandler.authenticateToken, async function (req, res, next) {
    try {
        let user = await userController.GetAnUserById(req.userId);
        if (!user) {
            res.status(404).send({
                message: "Không tìm thấy user"
            })
            return;
        }
        res.send({
            id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullName,
            avatarUrl: user.avatarUrl,
            status: user.status
        })
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

// Endpoint changePassword - Đổi mật khẩu
router.post('/changepassword', authHandler.authenticateToken, 
    body('oldPassword').notEmpty().withMessage('Old password is required'),
    body('newPassword')
        .notEmpty().withMessage('New password is required')
        .isLength({ min: 6 }).withMessage('New password must be at least 6 characters')
        .custom((value, { req }) => {
            if (value === req.body.oldPassword) {
                throw new Error('New password must be different from old password');
            }
            return true;
        }),
    async function (req, res, next) {
        try {
            // Kiểm tra lỗi validation
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            let { oldPassword, newPassword } = req.body;
            let user = await userController.GetAnUserById(req.userId);
            
            if (!user) {
                return res.status(404).send({
                    message: "Không tìm thấy user"
                })
            }

            // Kiểm tra mật khẩu cũ
            if (!bcrypt.compareSync(oldPassword, user.password)) {
                return res.status(401).send({
                    message: "Mật khẩu cũ không chính xác"
                })
            }

            // Cập nhật mật khẩu mới
            user.password = newPassword;
            await user.save();

            res.send({
                message: "Đổi mật khẩu thành công"
            })
        } catch (error) {
            res.status(400).send({
                message: error.message
            })
        }
    }
)

module.exports = router