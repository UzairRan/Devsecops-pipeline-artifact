pipeline {
    agent {
        docker {
            image 'devsecops-tools:latest'
            args '-u root --privileged -v /var/run/docker.sock:/var/run/docker.sock'
            reuseNode true
        }
    }

    environment {
        DOCKER_IMAGE = "devsecops-app"
        REPORT_DIR = "reports"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Verify Tools') {
            steps {
                sh '''
                echo "=== Security Tools Verification ==="
                python3 --version
                bandit --version
                trivy --version
                tfsec --version
                checkov --version
                gitleaks version
                echo "All tools ready!"
                '''
            }
        }

        stage('Build Application') {
            steps {
                sh 'docker build -t $DOCKER_IMAGE ./app'
            }
        }

        stage('Security Scans') {
            parallel {
                stage('SAST - Bandit') {
                    steps {
                        sh 'bandit -r app/src -f json -o ${REPORT_DIR}/bandit.json'
                    }
                }
                stage('Dependency Scan') {
                    steps {
                        sh 'pip-audit -r app/requirements.txt -f json -o ${REPORT_DIR}/pip-audit.json'
                    }
                }
                stage('Secret Scan') {
                    steps {
                        sh 'gitleaks detect --source . --report-path ${REPORT_DIR}/gitleaks.json'
                    }
                }
            }
        }

        stage('Container Security') {
            steps {
                sh '''
                trivy image --format json -o ${REPORT_DIR}/trivy.json $DOCKER_IMAGE
                trivy image --format cyclonedx -o ${REPORT_DIR}/sbom.json $DOCKER_IMAGE
                '''
            }
        }

        stage('Infrastructure Security') {
            steps {
                sh '''
                tfsec terraform --format json > ${REPORT_DIR}/tfsec.json
                checkov -d terraform -o json > ${REPORT_DIR}/checkov.json
                '''
            }
        }

        stage('Push to Docker Hub') {
            when {
                environment name: 'PUSH_TO_REGISTRY', value: 'true'
            }
            environment {
                DOCKER_USER = credentials('docker-hub')
            }
            steps {
                sh '''
                echo $DOCKER_USER_PSW | docker login -u $DOCKER_USER_USR --password-stdin
                docker tag $DOCKER_IMAGE $DOCKER_USER_USR/$DOCKER_IMAGE:latest
                docker push $DOCKER_USER_USR/$DOCKER_IMAGE:latest
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '${REPORT_DIR}/*.json', fingerprint: true
            junit '**/test-reports/*.xml'
        }
        success {
            echo 'Pipeline succeeded! Security reports generated.'
        }
        failure {
            echo 'Pipeline failed! Check logs above.'
        }
    }
} 