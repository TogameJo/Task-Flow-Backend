document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();

    // Lấy dữ liệu từ form đăng nhập
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Gửi yêu cầu đăng nhập
    fetch('/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            username: username,
            password: password
        })
    })
        .then(response => response.json())
        .then(data => {
            // Lưu JWT vào localStorage
            localStorage.setItem('jwt', data.token);
            // Chuyển hướng người dùng tới trang chủ sau khi đăng nhập thành công
            window.location.href = '/home';
        })
        .catch(error => {
            console.error('Login error:', error);
            alert('Login failed. Please try again.');
        });
});
