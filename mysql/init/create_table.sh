CREATE DATABASE IF NOT EXISTS $MYSQL_DATABASE;
USE $MYSQL_DATABASE;
CREATE TABLE IF NOT EXISTS hoge (
  name VARCHAR(255),
  password VARCHAR(255)
);
EOF