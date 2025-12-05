pipeline {

    agent {
        docker {
            image 'devsecops-tools:latest'   // your custom tools image
            args '-u root --privileged -v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

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
                echo "Environment ready — tools preinstalled in Docker agent."

                mkdir -p ${REPORT_DIR}

                # Verify tools
                python3 --version
                pip3 --version
                bandit --version
                gitleaks version || true
                trivy --version || true
                tfsec --version || true
                checkov --version || true
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

                tfsec terraform --format json > reports/tfsec-report.json || true
                checkov -d terraform -o json > reports/checkov-report.json || true
                '''
            }
        }

        stage('Sign Image (cosign)') {
            steps {
                sh '''
                which cosign || echo "cosign not installed — skipping signing"
                cosign verify --key cosign.pub $DOCKER_IMAGE || true
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
                echo $DOCKER_PASSWORD | docker login -u $DOCKER_USERNAME --password-stdin
                docker tag $DOCKER_IMAGE $DOCKER_USERNAME/$DOCKER_IMAGE:latest
                docker push $DOCKER_USERNAME/$DOCKER_IMAGE:latest
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
