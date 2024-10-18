
import torch.nn as nn


class AttentionBlock(nn.Module):
    def __init__(self, in_channels):
        super(AttentionBlock, self).__init__()
        self.attention = nn.Sequential(
            nn.Conv1d(in_channels, in_channels // 8, kernel_size=1),
            nn.ReLU(inplace=True),
            nn.Conv1d(in_channels // 8, in_channels, kernel_size=1),
            nn.Sigmoid()
        )

    def forward(self, x):
        attention = self.attention(x)
        return x * attention

class ResidualBlock(nn.Module):
    def __init__(self, in_channels, out_channels, stride=1, dilation=1, use_attention=False):
        super(ResidualBlock, self).__init__()
        self.use_attention = use_attention
        self.conv1 = nn.Conv1d(in_channels, out_channels, kernel_size=3, stride=stride, padding=dilation, dilation=dilation)
        self.bn1 = nn.BatchNorm1d(out_channels)
        self.conv2 = nn.Conv1d(out_channels, out_channels, kernel_size=3, stride=1, padding=dilation, dilation=dilation)
        self.bn2 = nn.BatchNorm1d(out_channels)
        self.relu = nn.ReLU(inplace=True)
        self.dropout = nn.Dropout(0.2)

        self.downsample = nn.Sequential(
            nn.Conv1d(in_channels, out_channels, kernel_size=1, stride=stride),
            nn.BatchNorm1d(out_channels)
        ) if stride != 1 or in_channels != out_channels else None

        if self.use_attention:
            self.attention = AttentionBlock(out_channels)

    def forward(self, x):
        residual = x
        out = self.conv1(x)
        out = self.bn1(out)
        out = self.relu(out)
        out = self.conv2(out)
        out = self.bn2(out)
        out = self.dropout(out)

        if self.downsample is not None:
            residual = self.downsample(x)

        out += residual
        out = self.relu(out)

        if self.use_attention:
            out = self.attention(out)

        return out

class LSTM_ResNet(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers, num_classes, dropout_prob=0.2, use_attention=False):
        super(LSTM_ResNet, self).__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, bidirectional=True, dropout=dropout_prob)
        self.res_block1 = ResidualBlock(2 * hidden_dim, 128, stride=2, use_attention=use_attention)
        self.res_block2 = ResidualBlock(128, 256, stride=2, use_attention=use_attention)
        self.res_block3 = ResidualBlock(256, 512, stride=2, use_attention=use_attention)
        self.dropout = nn.Dropout(dropout_prob)
        self.fc = nn.Linear(512, num_classes)
        self.relu = nn.ReLU(inplace=True)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = out.permute(0, 2, 1)  # 调整维度以适应Conv1d
        out = self.res_block1(out)
        out = self.res_block2(out)
        out = self.res_block3(out)
        out = out.mean(dim=2)  # 全局平均池化
        out = self.dropout(out)
        out = self.fc(out)
        return out

class EarlyStopping:
    def __init__(self, patience=10, verbose=False, delta=0):
        self.patience = patience
        self.verbose = verbose
        self.delta = delta
        self.best_loss = None
        self.counter = 0
        self.early_stop = False

    def __call__(self, val_loss):
        if self.best_loss is None:
            self.best_loss = val_loss
        elif val_loss > self.best_loss - self.delta:
            self.counter += 1
            if self.counter >= self.patience:
                self.early_stop = True
        else:
            self.best_loss = val_loss
            self.counter = 0
