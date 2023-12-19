# 安全数据库系统
该系统实现一个安全的数据库系统，对数据库进行数字签名保证完整性，数据加密保证隐秘性。

## 要求
1．数据库的数据要进行加密；
2. 对数据库的完整性进行保护；
3．防止用户根据部分密文明文对，恢复数据库总密钥；
4．数据采用一个密钥以某种形式衍生子密钥进行加密；
5．保证密钥的安全性。
说明：可以采用总密钥，根据hash函数，以及每一个数据的各种属性来产生子密钥。

## 数据库加密应用 (SecureDatabaseApp)

这个 Java 应用程序旨在演示如何使用 AES 加密算法对数据库中的数据进行加密和解密。

### 功能

#### 加密

1. **输入文本**: 在 "输入文本" 文本框中输入要加密的内容。
2. **加密按钮**: 点击 "加密" 按钮将使用总密钥和数据属性对输入文本进行加密。
3. **保存至数据库按钮**: 加密后的数据将保存到 MySQL 数据库中。

#### 解密

1. **显示数据库内容按钮**: 显示数据库中存储的加密数据。
2. **解密按钮**: 对于显示的加密数据，可以使用总密钥和数据属性进行解密并显示原始内容。
3. **解密输入按钮**: 可以输入已加密的内容并尝试解密。

### 使用方法

1. **环境准备**:
    - 确保已安装 Java 运行时环境。
    - 确保已安装 MySQL 数据库并配置了正确的用户名和密码。

2. **设置密钥**:
    - 密钥被硬编码为 "MyMasterKey123" 和 "SomeAttribute"，你可以根据需要更改它们。

3. **运行应用程序**:
    - 运行 `SecureDatabaseApp.java` 文件启动应用程序。

4. **使用应用程序**:
    - 输入要加密的文本并点击 "加密"，然后使用 "保存至数据库" 将其保存到数据库中。
    - 使用相应按钮解密数据库中的数据。

### 接入代码
    private JTextField inputText, outputText, decryptedText, inputEncryptedText; // 定义文本框的变量
    private JButton encryptButton, saveButton, decryptButton, showDBButton, decryptInputButton; // 定义按钮的变量
    private JTextArea databaseContent; // 定义文本域的变量
    private static final String KEYSTORE_FILE = "keystore.jce"; // 定义密钥库文件名
    private static final String KEY_ALIAS = "myKey"; // 定义密钥别名

    public SecureDatabaseApp() { // 定义SecureDatabaseApp类的构造函数
        setTitle("数据库加密应用"); // 设置窗口标题
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // 设置关闭操作
        setLayout(new BorderLayout()); // 设置布局为边界布局

        // 创建面板和各种组件并添加到窗口中
        JPanel inputPanel = new JPanel(new FlowLayout());
        JPanel outputPanel = new JPanel(new FlowLayout());
        JPanel decryptionPanel = new JPanel(new FlowLayout());
        JPanel databasePanel = new JPanel(new BorderLayout());

        inputText = new JTextField(20); // 创建输入文本框
        outputText = new JTextField(20); // 创建输出文本框
        outputText.setEditable(false); // 设置输出文本框为不可编辑
        decryptedText = new JTextField(20); // 创建解密文本框
        decryptedText.setEditable(false); // 设置解密文本框为不可编辑
        inputEncryptedText = new JTextField(20); // 创建输入加密文本框

        encryptButton = new JButton("加密"); // 创建加密按钮
        saveButton = new JButton("保存至数据库"); // 创建保存按钮
        decryptButton = new JButton("解密"); // 创建解密按钮
        showDBButton = new JButton("显示数据库内容"); // 创建显示数据库按钮
        decryptInputButton = new JButton("解密输入"); // 创建解密输入按钮

        databaseContent = new JTextArea(10, 30); // 创建数据库内容文本域
        databaseContent.setEditable(false); // 设置数据库内容文本域为不可编辑

        inputPanel.add(new JLabel("输入文本:")); // 添加标签和文本框到输入面板
        inputPanel.add(inputText);
        inputPanel.add(encryptButton); // 添加按钮到输入面板
        inputPanel.add(saveButton);

        outputPanel.add(new JLabel("加密后数据:")); // 添加标签和文本框到输出面板
        outputPanel.add(outputText);

        decryptionPanel.add(decryptButton); // 添加按钮和文本框到解密面板
        decryptionPanel.add(decryptedText);
        decryptionPanel.add(inputEncryptedText);
        decryptionPanel.add(decryptInputButton);

        databasePanel.add(new JLabel("数据库内容:"), BorderLayout.NORTH); // 添加标签和文本域到数据库面板
        databasePanel.add(new JScrollPane(databaseContent), BorderLayout.CENTER);
        databasePanel.add(showDBButton, BorderLayout.SOUTH);

        // 将各个面板添加到窗口中，并为按钮添加事件监听器
        add(inputPanel, BorderLayout.NORTH);
        add(outputPanel, BorderLayout.CENTER);
        add(decryptionPanel, BorderLayout.SOUTH);
        add(databasePanel, BorderLayout.EAST);

        encryptButton.addActionListener(e -> performEncryption()); // 添加加密按钮的事件监听器
        saveButton.addActionListener(e -> performSaveToDB()); // 添加保存按钮的事件监听器
        decryptButton.addActionListener(e -> performDecryption()); // 添加解密按钮的事件监听器
        showDBButton.addActionListener(e -> showDatabaseContent()); // 添加显示数据库按钮的事件监听器
        decryptInputButton.addActionListener(e -> performInputDecryption()); // 添加解密输入按钮的事件监听器

        pack(); // 调整窗口大小适应组件的首选大小
        setLocationRelativeTo(null); // 将窗口置于屏幕中央
        setVisible(true); // 设置窗口可见

        createTableIfNotExists(); // 检查数据库表是否存在，如果不存在则创建
        createKeyStore(); // 检查密钥库是否存在，如果不存在则创建
    }
    // 检查密钥存储，如果不存在则创建
    private void createKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS"); // 获取密钥库实例
            char[] password = "keystorePassword".toCharArray(); // 密钥库密码

            File keystoreFile = new File(KEYSTORE_FILE);
            if (!keystoreFile.exists()) { // 如果密钥库文件不存在
                keyStore.load(null, password); // 加载一个空密钥库

                // 生成密钥
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey key = keyGen.generateKey();
                KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
                keyStore.setEntry(KEY_ALIAS, keyEntry, new KeyStore.PasswordProtection(password));

                // 将密钥存储到文件
                try (FileOutputStream fos = new FileOutputStream(KEYSTORE_FILE)) {
                    keyStore.store(fos, password);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // 加载密钥
    private SecretKey getKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS"); // 获取密钥库实例
            char[] password = "keystorePassword".toCharArray(); // 密钥库密码

            try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
                keyStore.load(fis, password); // 加载密钥库文件
            }

            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS,
                    new KeyStore.PasswordProtection(password)); // 获取密钥条目
            return secretKeyEntry.getSecretKey(); // 返回密钥
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    // 导出密钥
    private byte[] deriveKey(String masterKey, String dataAttribute) {
        try {
            int iterations = 10000; // 迭代次数
            int keyLength = 256; // 生成的密钥长度

            String salt = dataAttribute + "_salt";

            KeySpec spec = new PBEKeySpec(masterKey.toCharArray(), salt.getBytes(), iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            return factory.generateSecret(spec).getEncoded();
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    // 执行加密操作
    private void performEncryption() {
        String data = inputText.getText(); // 获取输入文本

        try {
            String masterKey = "MyMasterKey123"; // 总密钥
            String dataAttribute = "SomeAttribute"; // 数据属性
            SecretKey key = getKey(); // 获取密钥
            byte[] derivedKey = deriveKey(masterKey, dataAttribute); // 导出密钥

            if (derivedKey != null) {
                Cipher cipher = Cipher.getInstance("AES"); // 创建加密器
                SecretKeySpec secretKeySpec = new SecretKeySpec(derivedKey, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec); // 初始化加密器

                byte[] encryptedData = cipher.doFinal(data.getBytes()); // 执行加密
                outputText.setText(new String(Base64.getEncoder().encode(encryptedData))); // 显示加密后的数据
            } else {
                System.out.println("Failed to derive key.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // 将加密数据保存到数据库
    private void performSaveToDB() {
        String encryptedData = outputText.getText(); // 获取加密后的数据

        try {
            String dbURL = "jdbc:mysql://localhost:3306/test"; // 数据库连接URL
            String username = "root"; // 数据库用户名
            String password = "123456"; // 数据库密码

            Connection connection = DriverManager.getConnection(dbURL, username, password); // 建立数据库连接
            createTableIfNotExists(); // 检查数据库表是否存在，如果不存在则创建

            String sql = "INSERT INTO data (encrypted_data) VALUES (?)"; // SQL语句
            PreparedStatement statement = connection.prepareStatement(sql); // 创建PreparedStatement对象
            statement.setString(1, encryptedData); // 设置参数
            int rowsInserted = statement.executeUpdate(); // 执行SQL语句

            if (rowsInserted > 0) {
                System.out.println("加密数据已保存到数据库。"); // 输出信息到控制台
            }

            statement.close(); // 关闭statement
            connection.close(); // 关闭connection
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }
    // 执行解密操作
    private void performDecryption() {
        String encryptedData = outputText.getText(); // 获取加密后的数据

        try {
            String masterKey = "MyMasterKey123"; // 总密钥
            String dataAttribute = "SomeAttribute"; // 数据属性

            byte[] derivedKey = deriveKey(masterKey, dataAttribute); // 导出密钥

            if (derivedKey != null) {
                Cipher cipher = Cipher.getInstance("AES"); // 创建解密器
                SecretKeySpec secretKeySpec = new SecretKeySpec(derivedKey, "AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec); // 初始化解密器

                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData)); // 执行解密
                String decryptedString = new String(decryptedBytes);
                decryptedText.setText(decryptedString); // 显示解密后的数据
            } else {
                System.out.println("Failed to derive key.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // 执行输入解密操作
    private void performInputDecryption() {
        String encryptedData = inputEncryptedText.getText(); // 获取输入的加密数据

        try {
            String masterKey = "MyMasterKey123"; // 总密钥
            String dataAttribute = "SomeAttribute"; // 数据属性

            byte[] derivedKey = deriveKey(masterKey, dataAttribute); // 导出密钥

            if (derivedKey != null) {
                Cipher cipher = Cipher.getInstance("AES"); // 创建解密器
                SecretKeySpec secretKeySpec = new SecretKeySpec(derivedKey, "AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec); // 初始化解密器

                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData)); // 执行解密
                String decryptedString = new String(decryptedBytes);
                decryptedText.setText(decryptedString); // 显示解密后的数据
            } else {
                System.out.println("Failed to derive key.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // 显示数据库内容
    private void showDatabaseContent() {
        try {
            String dbURL = "jdbc:mysql://localhost:3306/test"; // 数据库连接URL
            String username = "root"; // 数据库用户名
            String password = "123456"; // 数据库密码

            Connection connection = DriverManager.getConnection(dbURL, username, password); // 建立数据库连接
            createTableIfNotExists(); // 检查数据库表是否存在，如果不存在则创建

            Statement statement = connection.createStatement(); // 创建Statement对象

            ResultSet resultSet = statement.executeQuery("SELECT encrypted_data FROM data"); // 执行查询
            StringBuilder content = new StringBuilder(); // 创建StringBuilder存储查询结果

            while (resultSet.next()) {
                String encryptedData = resultSet.getString("encrypted_data");
                content.append(encryptedData).append("\n"); // 将结果添加到StringBuilder中
            }

            databaseContent.setText(content.toString()); // 在文本域中显示结果

            resultSet.close(); // 关闭resultSet
            statement.close(); // 关闭statement
            connection.close(); // 关闭connection
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    // 创建数据表（如果不存在）
    private void createTableIfNotExists() {
        try {
            String dbURL = "jdbc:mysql://localhost:3306/test"; // 数据库连接URL
            String username = "root"; // 数据库用户名
            String password = "123456"; // 数据库密码

            Connection connection = DriverManager.getConnection(dbURL, username, password); // 建立数据库连接

            String createTableSQL = "CREATE TABLE IF NOT EXISTS data (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY," +
                    "encrypted_data VARCHAR(1000)" +
                    ")"; // SQL语句：创建数据表

            Statement statement = connection.createStatement(); // 创建Statement对象
            statement.execute(createTableSQL); // 执行SQL语句创建数据表

            statement.close(); // 关闭statement
            connection.close(); // 关闭connection
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SecureDatabaseApp::new); // 启动Swing应用程序
    }
    
## 注意事项

- 密钥和密码硬编码在代码中，这只是一个演示。在实际应用中，应该更安全地管理和存储密钥。
- 此代码用于演示目的，实际应用中可能需要更多安全性和异常处理。
