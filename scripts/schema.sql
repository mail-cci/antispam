CREATE TABLE IF NOT EXISTS emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    correlation_id VARCHAR(255),
    envelope_from VARCHAR(255),
    client_ip VARCHAR(45),
    helo VARCHAR(255),
    received_at DATETIME,
    body MEDIUMTEXT
);

CREATE TABLE IF NOT EXISTS email_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    name VARCHAR(255),
    value TEXT,
    FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS email_attachments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    filename VARCHAR(255),
    content_type VARCHAR(255),
    content LONGBLOB,
    FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS spam_scores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    engine VARCHAR(255),
    score DOUBLE,
    threshold DOUBLE,
    is_spam BOOLEAN,
    FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS quarantine (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    reason TEXT,
    quarantined_at DATETIME,
    FOREIGN KEY (email_id) REFERENCES emails(id)
);
