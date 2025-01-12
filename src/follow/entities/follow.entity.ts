import { Entity, PrimaryGeneratedColumn, ManyToOne, Column } from 'typeorm';
import { User } from '../../user/entities/user.entity';

@Entity('follows')
export class Follow {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.following, { onDelete: 'CASCADE' })
  follower: User;

  @ManyToOne(() => User, (user) => user.followers, { onDelete: 'CASCADE' })
  following: User;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
