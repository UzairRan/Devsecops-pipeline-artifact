pipeline {
    agent any  // ← ONLY this line, remove commented docker block!

    environment {
        DOCKER_IMAGE = "devsecops-app"
        REPORT_DIR = "reports"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/UzairRan/Devsecops-pipeline-artifact.git' 
            }
        }

        stage('Prepare') {
            steps {
                sh '''
                echo "Environment ready — installing tools..."

                mkdir -p ${REPORT_DIR}

                # Install tools if missing (for agent any)
                apk add python3 py3-pip docker || true
                pip3 install bandit pip-audit pytest checkov || true

                # Verify tools
                python3 --version
                pip3 --version
                bandit --version || echo "bandit not found"
                '''
            }
        }

        stage('Build Docker') {
            steps {
                sh 'docker build -t $DOCKER_IMAGE ./app'
            }
        }

        stage('Unit Tests') {
            steps {
                sh 'pytest -q --disable-warnings --maxfail=1 || true'
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh 'bandit -r app/src -f json -o reports/bandit-report.json || true'
            }
        }

        stage('Dependency Scan - pip-audit') {
            steps {
                sh 'pip-audit -r app/requirements.txt -f json -o reports/pip-audit-report.json || true'
            }
        }

        stage('Secret Scan - Gitleaks') {
            steps {
                sh 'gitleaks detect -v --report-path reports/gitleaks-report.json || true'
            }
        }

        stage('Container Scan - Trivy') {
            steps {
                sh 'trivy image --format json -o reports/trivy-report.json $DOCKER_IMAGE || true'
            }
        }

        stage('SBOM') {
            steps {
                sh 'trivy image --format cyclonedx --output reports/sbom.json $DOCKER_IMAGE || true'
            }
        }

        stage('Terraform Security Scan') {
            steps {
                sh '''
                echo "Running Terraform Security Scans..."
                # Install terraform tools if missing
                wget https://github.com/aquasecurity/tfsec/releases/download/v1.28.6/tfsec_1.28.6_linux_amd64.tar.gz -O tfsec.tar.gz || true
                tar -xzf tfsec.tar.gz tfsec || true
                chmod +x tfsec || true
                ./tfsec terraform --format json > reports/tfsec-report.json || true
                '''
            }
        }

        stage('Sign Image (cosign)') {
            steps {
                sh '''
                which cosign || echo "cosign not installed — skipping signing"
                '''
            }
        }

        stage('Push Docker') {
            environment {
                DOCKER_USERNAME = credentials('docker-username')
                DOCKER_PASSWORD = credentials('docker-password')
            }
            steps {
                sh '''
                echo $DOCKER_PASSWORD | docker login -u $DOCKER_USERNAME --password-stdin || true
                docker tag $DOCKER_IMAGE $DOCKER_USERNAME/$DOCKER_IMAGE:latest || true
                docker push $DOCKER_USERNAME/$DOCKER_IMAGE:latest || true
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*.json', fingerprint: true
            junit allowEmptyResults: true, testResults: '**/test-*.xml'
        }
    }
} 